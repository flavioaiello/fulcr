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
        .map(|config| archive_dir.join(config))
        .filter(|path| path.exists())
        .map(|path| file_digest(&path))
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
        let layer_path = archive_dir.join(layer);
        unpack_tar(&layer_path, rootfs, true)
            .with_context(|| format!("unpacking Docker layer {layer}"))?;
        let (digest, size) = file_digest(&layer_path)?;
        layers.push(ImageLayerMetadata {
            digest,
            media_type: Some("application/vnd.docker.image.rootfs.diff.tar".to_string()),
            size,
        });
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
    let reader = archive_reader(path)?;
    let mut archive = tar::Archive::new(reader);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?.into_owned();
        let Some(relative) = safe_relative_path(&entry_path) else {
            continue;
        };

        if apply_whiteouts && apply_whiteout(destination, &relative)? {
            continue;
        }

        let target = destination.join(relative);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        
        let header_type = entry.header().entry_type();
        if header_type.is_symlink() || header_type.is_hard_link() {
            continue; // Skip symlinks and hardlinks to prevent relative path breakouts
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
        remove_path(&rootfs.join(parent).join(target_name))?;
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
    let path = archive_dir.join("blobs").join(algorithm).join(value);
    if !path.exists() {
        bail!("OCI blob not found for digest {digest}")
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

