use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

use anyhow::{bail, Context};
use flate2::read::GzDecoder;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zstd::stream::read::Decoder as ZstdDecoder;

use crate::models::{ImageLayerMetadata, ImageScanMetadata};

const DEFAULT_TAR_LIMITS: TarLimits = TarLimits {
    max_entries: 100_000,
    max_unpacked_bytes: 1_073_741_824,
};

#[derive(Clone, Copy)]
struct TarLimits {
    max_entries: u64,
    max_unpacked_bytes: u64,
}

pub struct UnpackedImage {
    pub rootfs: PathBuf,
    pub metadata: ImageScanMetadata,
    _temp: TempDir,
}

pub fn unpack_image_archive(archive_path: &Path) -> anyhow::Result<UnpackedImage> {
    let archive_path = fs::canonicalize(archive_path)
        .with_context(|| format!("canonicalizing image archive {}", archive_path.display()))?;
    let temp = tempfile::tempdir().context("creating image unpack workspace")?;
    let archive_dir = temp.path().join("archive");
    let rootfs = temp.path().join("rootfs");
    fs::create_dir_all(&archive_dir)?;
    fs::create_dir_all(&rootfs)?;

    unpack_tar(&archive_path, &archive_dir, false).context("unpacking image archive")?;

    let metadata = if archive_dir.join("manifest.json").exists() {
        reconstruct_docker_archive(&archive_path, &archive_dir, &rootfs)?
    } else if archive_dir.join("oci-layout").exists() && archive_dir.join("index.json").exists() {
        reconstruct_oci_archive(&archive_path, &archive_dir, &rootfs)?
    } else {
        bail!("image archive is neither Docker save format nor OCI image layout archive")
    };

    Ok(UnpackedImage {
        rootfs,
        metadata,
        _temp: temp,
    })
}

fn reconstruct_docker_archive(
    archive_path: &Path,
    archive_dir: &Path,
    rootfs: &Path,
) -> anyhow::Result<ImageScanMetadata> {
    let manifest_path = archive_dir.join("manifest.json");
    let manifest_bytes = fs::read(&manifest_path).context("reading Docker manifest.json")?;
    let manifest =
        serde_json::from_slice::<Value>(&manifest_bytes).context("parsing Docker manifest.json")?;
    let Some(entry) = manifest.as_array().and_then(|items| items.first()) else {
        bail!("Docker manifest.json did not contain an image entry")
    };

    let tags = entry
        .get("RepoTags")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let config_digest = entry
        .get("Config")
        .and_then(Value::as_str)
        .map(|config| {
            docker_archive_member_path(archive_dir, config).and_then(|path| file_digest(&path))
        })
        .transpose()?
        .map(|(digest, _)| digest);

    let mut layers = Vec::new();
    for layer in entry
        .get("Layers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        let layer_path = docker_archive_member_path(archive_dir, layer)?;
        unpack_tar(&layer_path, rootfs, true)
            .with_context(|| format!("unpacking Docker layer {layer}"))?;
        let (digest, size) = file_digest(&layer_path)?;
        layers.push(ImageLayerMetadata {
            digest,
            media_type: Some("application/vnd.docker.image.rootfs.diff.tar".to_string()),
            size,
        });
    }

    fn docker_archive_member_path(archive_dir: &Path, member: &str) -> anyhow::Result<PathBuf> {
        let Some(relative) = safe_relative_path(Path::new(member)) else {
            bail!("unsafe Docker archive member path {member}")
        };
        let path = archive_dir.join(relative);
        let canonical = fs::canonicalize(&path)
            .with_context(|| format!("canonicalizing Docker archive member {member}"))?;
        let archive_dir = fs::canonicalize(archive_dir).with_context(|| {
            format!("canonicalizing archive directory {}", archive_dir.display())
        })?;
        if !canonical.starts_with(&archive_dir) {
            bail!("Docker archive member {member} escapes the unpacked archive directory")
        }
        Ok(canonical)
    }

    Ok(ImageScanMetadata {
        kind: "docker-archive".to_string(),
        archive: archive_path.to_path_buf(),
        manifest_digest: Some(crate::digest::digest_bytes(&manifest_bytes)),
        config_digest,
        tags,
        layers,
    })
}

fn reconstruct_oci_archive(
    archive_path: &Path,
    archive_dir: &Path,
    rootfs: &Path,
) -> anyhow::Result<ImageScanMetadata> {
    let index = read_json(archive_dir.join("index.json"))?;
    let Some(manifest_descriptor) = index
        .get("manifests")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
    else {
        bail!("OCI index.json did not contain a manifest descriptor")
    };
    let manifest_digest = manifest_descriptor
        .get("digest")
        .and_then(Value::as_str)
        .context("OCI manifest descriptor missing digest")?
        .to_string();
    let manifest_path = blob_path(archive_dir, &manifest_digest)?;
    let manifest = read_json(&manifest_path)?;
    let config_digest = manifest
        .get("config")
        .and_then(|config| config.get("digest"))
        .and_then(Value::as_str)
        .map(str::to_string);
    if let Some(digest) = config_digest.as_deref() {
        let _ = blob_path(archive_dir, digest)?;
    }
    let tags = manifest_descriptor
        .get("annotations")
        .and_then(|annotations| annotations.get("org.opencontainers.image.ref.name"))
        .and_then(Value::as_str)
        .map(|tag| vec![tag.to_string()])
        .unwrap_or_default();

    let mut layers = Vec::new();
    for layer in manifest
        .get("layers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let digest = layer
            .get("digest")
            .and_then(Value::as_str)
            .context("OCI layer descriptor missing digest")?
            .to_string();
        let layer_path = blob_path(archive_dir, &digest)?;
        unpack_tar(&layer_path, rootfs, true)
            .with_context(|| format!("unpacking OCI layer {digest}"))?;
        let size = fs::metadata(&layer_path)?.len();
        if let Some(expected_size) = layer.get("size").and_then(Value::as_u64) {
            if expected_size != size {
                bail!(
                    "OCI layer {digest} size mismatch: descriptor declared {expected_size}, found {size}"
                );
            }
        }
        layers.push(ImageLayerMetadata {
            digest,
            media_type: layer
                .get("mediaType")
                .and_then(Value::as_str)
                .map(str::to_string),
            size,
        });
    }

    Ok(ImageScanMetadata {
        kind: "oci-archive".to_string(),
        archive: archive_path.to_path_buf(),
        manifest_digest: Some(manifest_digest),
        config_digest,
        tags,
        layers,
    })
}

fn unpack_tar(path: &Path, destination: &Path, apply_whiteouts: bool) -> anyhow::Result<()> {
    unpack_tar_with_limits(path, destination, apply_whiteouts, DEFAULT_TAR_LIMITS)
}

fn unpack_tar_with_limits(
    path: &Path,
    destination: &Path,
    apply_whiteouts: bool,
    limits: TarLimits,
) -> anyhow::Result<()> {
    let reader = archive_reader(path)?;
    let mut archive = tar::Archive::new(reader);
    let mut entries_seen = 0_u64;
    let mut unpacked_bytes = 0_u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        entries_seen = entries_seen.saturating_add(1);
        if entries_seen > limits.max_entries {
            bail!("tar archive exceeded entry limit of {}", limits.max_entries);
        }

        let entry_path = entry.path()?.into_owned();
        let Some(relative) = safe_relative_path(&entry_path) else {
            continue;
        };

        if apply_whiteouts && apply_whiteout(destination, &relative)? {
            continue;
        }

        let header_type = entry.header().entry_type();
        if header_type.is_symlink() || header_type.is_hard_link() {
            continue; // Skip symlinks and hardlinks to prevent relative path breakouts
        }
        if !header_type.is_file() && !header_type.is_dir() {
            bail!("unsupported tar entry type at {}", relative.display());
        }

        let target = destination.join(&relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }

        let entry_size = entry.header().size()?;
        unpacked_bytes = unpacked_bytes.saturating_add(entry_size);
        if unpacked_bytes > limits.max_unpacked_bytes {
            bail!(
                "tar archive exceeded unpacked byte limit of {}",
                limits.max_unpacked_bytes
            );
        }

        entry.unpack(&target)?;
    }
    Ok(())
}

fn apply_whiteout(rootfs: &Path, relative: &Path) -> anyhow::Result<bool> {
    let Some(file_name) = relative.file_name().and_then(|name| name.to_str()) else {
        return Ok(false);
    };
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));

    if file_name == ".wh..wh..opq" {
        let opaque_dir = rootfs.join(parent);
        if opaque_dir.is_dir() {
            for entry in fs::read_dir(opaque_dir)? {
                let path = entry?.path();
                remove_path(&path)?;
            }
        }
        return Ok(true);
    }

    if let Some(target_name) = file_name.strip_prefix(".wh.") {
        let target_relative = Path::new(target_name);
        if !matches!(
            target_relative.components().next(),
            Some(Component::Normal(_))
        ) || target_relative.components().nth(1).is_some()
        {
            bail!("unsafe whiteout target {target_name}");
        }
        remove_path(&rootfs.join(parent).join(target_relative))?;
        return Ok(true);
    }

    Ok(false)
}

fn remove_path(path: &Path) -> anyhow::Result<()> {
    if path.is_dir() && !path.is_symlink() {
        fs::remove_dir_all(path).or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        })?;
    } else {
        fs::remove_file(path).or_else(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                Ok(())
            } else {
                Err(error)
            }
        })?;
    }
    Ok(())
}

fn archive_reader(path: &Path) -> anyhow::Result<Box<dyn Read>> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0_u8; 4];
    let read = file.read(&mut magic)?;
    file.seek(SeekFrom::Start(0))?;
    if read >= 2 && magic[..2] == [0x1f, 0x8b] {
        Ok(Box::new(GzDecoder::new(file)))
    } else if read == 4 && magic == [0x28, 0xb5, 0x2f, 0xfd] {
        Ok(Box::new(ZstdDecoder::new(file)?))
    } else {
        Ok(Box::new(file))
    }
}

fn read_json(path: impl AsRef<Path>) -> anyhow::Result<Value> {
    let path = path.as_ref();
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parsing {}", path.display()))
}

fn blob_path(archive_dir: &Path, digest: &str) -> anyhow::Result<PathBuf> {
    let Some((algorithm, value)) = digest.split_once(':') else {
        bail!("invalid OCI digest {digest}")
    };
    if algorithm != "sha256" {
        bail!("unsupported OCI digest algorithm {algorithm}")
    }
    let path = archive_dir.join("blobs").join(algorithm).join(value);
    if !path.exists() {
        bail!("OCI blob not found for digest {digest}")
    }
    let (actual, _) = file_digest(&path)?;
    if actual != digest {
        bail!("OCI blob digest mismatch for {digest}: found {actual}")
    }
    Ok(path)
}

fn safe_relative_path(path: &Path) -> Option<PathBuf> {
    let mut relative = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => relative.push(value),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!relative.as_os_str().is_empty()).then_some(relative)
}

fn file_digest(path: &Path) -> anyhow::Result<(String, u64)> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        size += read as u64;
    }
    Ok((format!("sha256:{}", hex::encode(digest.finalize())), size))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blob_path_accepts_matching_sha256_digest() {
        let temp = tempfile::tempdir().unwrap();
        let bytes = b"layer bytes";
        let digest = crate::digest::digest_bytes(bytes);
        let (_, value) = digest.split_once(':').unwrap();
        let blob_dir = temp.path().join("blobs").join("sha256");
        std::fs::create_dir_all(&blob_dir).unwrap();
        let path = blob_dir.join(value);
        std::fs::write(&path, bytes).unwrap();

        assert_eq!(blob_path(temp.path(), &digest).unwrap(), path);
    }

    #[test]
    fn blob_path_rejects_sha256_digest_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let digest = format!("sha256:{}", "0".repeat(64));
        let (_, value) = digest.split_once(':').unwrap();
        let blob_dir = temp.path().join("blobs").join("sha256");
        std::fs::create_dir_all(&blob_dir).unwrap();
        std::fs::write(blob_dir.join(value), b"different layer bytes").unwrap();

        let error = blob_path(temp.path(), &digest).unwrap_err().to_string();
        assert!(error.contains("OCI blob digest mismatch"));
    }

    #[test]
    fn docker_archive_rejects_manifest_path_escape() {
        let temp = tempfile::tempdir().unwrap();
        let image_dir = temp.path().join("image");
        std::fs::create_dir_all(&image_dir).unwrap();
        std::fs::write(image_dir.join("config.json"), "{}").unwrap();
        std::fs::write(
            image_dir.join("manifest.json"),
            r#"[{"Config":"config.json","RepoTags":["service:test"],"Layers":["../layer.tar"]}]"#,
        )
        .unwrap();
        let image_archive = temp.path().join("image.tar");
        {
            let file = std::fs::File::create(&image_archive).unwrap();
            let mut archive = tar::Builder::new(file);
            archive
                .append_path_with_name(image_dir.join("config.json"), "config.json")
                .unwrap();
            archive
                .append_path_with_name(image_dir.join("manifest.json"), "manifest.json")
                .unwrap();
            archive.finish().unwrap();
        }

        let error = match unpack_image_archive(&image_archive) {
            Ok(_) => panic!("expected Docker archive path escape to be rejected"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("unsafe Docker archive member path"));
    }

    #[test]
    fn unpack_tar_rejects_archives_over_byte_limit() {
        let temp = tempfile::tempdir().unwrap();
        let tar_path = temp.path().join("oversized.tar");
        {
            let file = std::fs::File::create(&tar_path).unwrap();
            let mut archive = tar::Builder::new(file);
            let bytes = b"too-large";
            let mut header = tar::Header::new_gnu();
            header.set_path("payload.txt").unwrap();
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            archive.append(&header, &bytes[..]).unwrap();
            archive.finish().unwrap();
        }

        let error = unpack_tar_with_limits(
            &tar_path,
            &temp.path().join("out"),
            false,
            TarLimits {
                max_entries: 10,
                max_unpacked_bytes: 4,
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("unpacked byte limit"));
    }

    #[test]
    fn whiteout_rejects_parent_directory_target() {
        let temp = tempfile::tempdir().unwrap();
        let rootfs = temp.path().join("rootfs");
        std::fs::create_dir_all(rootfs.join("dir")).unwrap();
        std::fs::write(rootfs.join("keep.txt"), b"keep").unwrap();

        let error = apply_whiteout(&rootfs, Path::new("dir/.wh..."))
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsafe whiteout target"));
        assert!(rootfs.join("keep.txt").exists());
    }
}
