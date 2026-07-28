use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::{Component, Path, PathBuf},
};

use anyhow::{Context, bail};
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
const MAX_IMAGE_LAYERS: usize = 512;
const MAX_PATH_COMPONENTS: usize = 256;
const MAX_COMPRESSION_RATIO: u64 = 200;
const MIN_COMPRESSION_ALLOWANCE: u64 = 64 * 1024 * 1024;

#[derive(Clone, Copy)]
struct TarLimits {
    max_entries: u64,
    max_unpacked_bytes: u64,
}

#[derive(Default)]
struct TarBudget {
    entries_seen: u64,
    unpacked_bytes: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Compression {
    None,
    Gzip,
    Zstd,
}

pub struct UnpackedImage {
    pub rootfs: PathBuf,
    pub metadata: ImageScanMetadata,
    _temp: TempDir,
}

pub struct UnpackedLayer {
    pub rootfs: PathBuf,
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

pub fn unpack_layer_archive(layer_path: &Path) -> anyhow::Result<UnpackedLayer> {
    let layer_path = fs::canonicalize(layer_path)
        .with_context(|| format!("canonicalizing layer archive {}", layer_path.display()))?;
    let temp = tempfile::tempdir().context("creating layer unpack workspace")?;
    let rootfs = temp.path().join("rootfs");
    fs::create_dir(&rootfs)?;
    unpack_tar(&layer_path, &rootfs, true).context("unpacking OCI layer artifact")?;
    Ok(UnpackedLayer {
        rootfs,
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
    let config_member = entry
        .get("Config")
        .and_then(Value::as_str)
        .context("Docker manifest entry missing Config")?;
    let config_path = docker_archive_member_path(archive_dir, config_member)?;
    let config_digest = Some(file_digest(&config_path)?.0);
    let expected_diff_ids = required_config_diff_ids(&read_json(&config_path)?)?;

    let layer_entries = entry
        .get("Layers")
        .and_then(Value::as_array)
        .context("Docker manifest entry missing Layers")?;
    if layer_entries.len() > MAX_IMAGE_LAYERS {
        bail!("Docker image exceeded layer limit of {MAX_IMAGE_LAYERS}");
    }

    let mut layers = Vec::new();
    let mut budget = TarBudget::default();
    for (index, layer) in layer_entries.iter().filter_map(Value::as_str).enumerate() {
        let layer_path = docker_archive_member_path(archive_dir, layer)?;
        unpack_tar_with_budget(&layer_path, rootfs, true, DEFAULT_TAR_LIMITS, &mut budget)
            .with_context(|| format!("unpacking Docker layer {layer}"))?;
        let (digest, size) = file_digest(&layer_path)?;
        let diff_id = uncompressed_file_digest(&layer_path)?;
        if let Some(expected) = expected_diff_ids.get(index)
            && expected != &diff_id
        {
            bail!(
                "Docker layer {layer} diff ID mismatch: config declared {expected}, found {diff_id}"
            );
        }
        layers.push(ImageLayerMetadata {
            digest,
            diff_id: Some(diff_id),
            media_type: Some(docker_layer_media_type(compression(&layer_path)?).to_string()),
            size,
        });
    }
    if expected_diff_ids.len() != layers.len() {
        bail!(
            "Docker config declared {} diff IDs for {} layers",
            expected_diff_ids.len(),
            layers.len()
        );
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
    let manifest_media_type = manifest_descriptor
        .get("mediaType")
        .and_then(Value::as_str)
        .context("OCI manifest descriptor missing mediaType")?;
    if !matches!(
        manifest_media_type,
        "application/vnd.oci.image.manifest.v1+json"
            | "application/vnd.docker.distribution.manifest.v2+json"
    ) {
        bail!("unsupported OCI manifest media type {manifest_media_type}");
    }
    let manifest_path = blob_path(archive_dir, &manifest_digest)?;
    validate_descriptor_size(manifest_descriptor, &manifest_path, "manifest")?;
    let manifest = read_json(&manifest_path)?;
    let config_descriptor = manifest
        .get("config")
        .context("OCI manifest missing config descriptor")?;
    let config_media_type = config_descriptor
        .get("mediaType")
        .and_then(Value::as_str)
        .context("OCI config descriptor missing mediaType")?;
    if !matches!(
        config_media_type,
        "application/vnd.oci.image.config.v1+json"
            | "application/vnd.docker.container.image.v1+json"
    ) {
        bail!("unsupported OCI config media type {config_media_type}");
    }
    let config_digest = config_descriptor
        .get("digest")
        .and_then(Value::as_str)
        .context("OCI config descriptor missing digest")?
        .to_string();
    let config_path = blob_path(archive_dir, &config_digest)?;
    validate_descriptor_size(config_descriptor, &config_path, "config")?;
    let expected_diff_ids = required_config_diff_ids(&read_json(config_path)?)?;
    let tags = manifest_descriptor
        .get("annotations")
        .and_then(|annotations| annotations.get("org.opencontainers.image.ref.name"))
        .and_then(Value::as_str)
        .map(|tag| vec![tag.to_string()])
        .unwrap_or_default();

    let layer_entries = manifest
        .get("layers")
        .and_then(Value::as_array)
        .context("OCI manifest missing layers")?;
    if layer_entries.len() > MAX_IMAGE_LAYERS {
        bail!("OCI image exceeded layer limit of {MAX_IMAGE_LAYERS}");
    }

    let mut layers = Vec::new();
    let mut budget = TarBudget::default();
    for (index, layer) in layer_entries.iter().enumerate() {
        let digest = layer
            .get("digest")
            .and_then(Value::as_str)
            .context("OCI layer descriptor missing digest")?
            .to_string();
        let layer_path = blob_path(archive_dir, &digest)?;
        validate_descriptor_size(layer, &layer_path, "layer")?;
        let declared_media_type = layer
            .get("mediaType")
            .and_then(Value::as_str)
            .context("OCI layer descriptor missing mediaType")?;
        validate_layer_media_type(declared_media_type, compression(&layer_path)?)?;
        unpack_tar_with_budget(&layer_path, rootfs, true, DEFAULT_TAR_LIMITS, &mut budget)
            .with_context(|| format!("unpacking OCI layer {digest}"))?;
        let size = fs::metadata(&layer_path)?.len();
        let diff_id = uncompressed_file_digest(&layer_path)?;
        if let Some(expected) = expected_diff_ids.get(index)
            && expected != &diff_id
        {
            bail!(
                "OCI layer {digest} diff ID mismatch: config declared {expected}, found {diff_id}"
            );
        }
        layers.push(ImageLayerMetadata {
            digest,
            diff_id: Some(diff_id),
            media_type: Some(declared_media_type.to_string()),
            size,
        });
    }
    if expected_diff_ids.len() != layers.len() {
        bail!(
            "OCI config declared {} diff IDs for {} layers",
            expected_diff_ids.len(),
            layers.len()
        );
    }

    Ok(ImageScanMetadata {
        kind: "oci-archive".to_string(),
        archive: archive_path.to_path_buf(),
        manifest_digest: Some(manifest_digest),
        config_digest: Some(config_digest),
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
    let mut budget = TarBudget::default();
    unpack_tar_with_budget(path, destination, apply_whiteouts, limits, &mut budget)
}

fn unpack_tar_with_budget(
    path: &Path,
    destination: &Path,
    apply_whiteouts: bool,
    limits: TarLimits,
    budget: &mut TarBudget,
) -> anyhow::Result<()> {
    let input_compression = compression(path)?;
    let compressed_size = fs::metadata(path)?.len();
    let starting_unpacked_bytes = budget.unpacked_bytes;
    let reader = archive_reader(path)?;
    let mut archive = tar::Archive::new(reader);
    let mut pending_hard_links = Vec::new();
    for entry in archive.entries()? {
        let mut entry = entry?;
        budget.entries_seen = budget.entries_seen.saturating_add(1);
        if budget.entries_seen > limits.max_entries {
            bail!("tar archive exceeded entry limit of {}", limits.max_entries);
        }

        let entry_path = entry.path()?.into_owned();
        let Some(relative) = safe_relative_path(&entry_path) else {
            continue;
        };

        create_safe_parent(
            destination,
            relative.parent().unwrap_or_else(|| Path::new("")),
        )?;

        if apply_whiteouts && apply_whiteout(destination, &relative)? {
            continue;
        }

        let header_type = entry.header().entry_type();
        let target = destination.join(&relative);

        let entry_size = entry.header().size()?;
        budget.unpacked_bytes = budget.unpacked_bytes.saturating_add(entry_size);
        if budget.unpacked_bytes > limits.max_unpacked_bytes {
            bail!(
                "tar archive exceeded unpacked byte limit of {}",
                limits.max_unpacked_bytes
            );
        }
        if input_compression != Compression::None {
            let archive_unpacked_bytes = budget
                .unpacked_bytes
                .saturating_sub(starting_unpacked_bytes);
            let ratio_limit = compressed_size
                .saturating_mul(MAX_COMPRESSION_RATIO)
                .max(MIN_COMPRESSION_ALLOWANCE);
            if archive_unpacked_bytes > ratio_limit {
                bail!("compressed tar exceeded expansion ratio limit of {MAX_COMPRESSION_RATIO}:1");
            }
        }

        if header_type.is_symlink() {
            let link_name = entry
                .link_name()?
                .context("tar symlink is missing its target")?;
            validate_symlink_target(
                relative.parent().unwrap_or_else(|| Path::new("")),
                &link_name,
            )?;
            remove_path(&target)?;
            create_symlink(&link_name, &target)?;
            continue;
        }
        if header_type.is_hard_link() {
            let link_name = entry
                .link_name()?
                .context("tar hard link is missing its target")?;
            let Some(link_name) = safe_relative_path(&link_name) else {
                bail!("unsafe hard link target {}", link_name.display());
            };
            pending_hard_links.push((target, link_name));
            continue;
        }
        if !header_type.is_file() && !header_type.is_dir() {
            bail!("unsupported tar entry type at {}", relative.display());
        }

        if header_type.is_file() {
            remove_path(&target)?;
        } else if let Ok(metadata) = fs::symlink_metadata(&target)
            && (metadata.file_type().is_symlink() || !metadata.is_dir())
        {
            remove_path(&target)?;
        }

        entry.unpack(&target)?;
    }

    for (target, link_name) in pending_hard_links {
        let source = destination.join(link_name);
        let metadata = fs::symlink_metadata(&source)
            .with_context(|| format!("reading hard link source {}", source.display()))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            bail!("hard link source is not a regular in-root file");
        }
        remove_path(&target)?;
        fs::hard_link(&source, &target)?;
    }
    Ok(())
}

fn create_safe_parent(root: &Path, relative: &Path) -> anyhow::Result<()> {
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let Component::Normal(component) = component else {
            bail!("unsafe parent path {}", relative.display());
        };
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
            Ok(_) => bail!(
                "archive parent is not a real directory: {}",
                current.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current)?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn validate_symlink_target(parent: &Path, target: &Path) -> anyhow::Result<()> {
    let mut depth = parent.components().count();
    for component in target.components() {
        match component {
            Component::Normal(_) => depth = depth.saturating_add(1),
            Component::CurDir => {}
            Component::ParentDir if depth > 0 => depth -= 1,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                bail!("symlink target escapes rootfs: {}", target.display())
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> anyhow::Result<()> {
    std::os::unix::fs::symlink(target, link)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, _link: &Path) -> anyhow::Result<()> {
    bail!("OCI layer symlinks are not supported on this platform")
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
    let compression = compression(path)?;
    let file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    if matches!(compression, Compression::Gzip) {
        Ok(Box::new(GzDecoder::new(file)))
    } else if matches!(compression, Compression::Zstd) {
        Ok(Box::new(ZstdDecoder::new(file)?))
    } else {
        Ok(Box::new(file))
    }
}

fn compression(path: &Path) -> anyhow::Result<Compression> {
    let mut file = File::open(path).with_context(|| format!("opening {}", path.display()))?;
    let mut magic = [0_u8; 4];
    let read = file.read(&mut magic)?;
    file.seek(SeekFrom::Start(0))?;
    if read >= 2 && magic[..2] == [0x1f, 0x8b] {
        Ok(Compression::Gzip)
    } else if read == 4 && magic == [0x28, 0xb5, 0x2f, 0xfd] {
        Ok(Compression::Zstd)
    } else {
        Ok(Compression::None)
    }
}

fn docker_layer_media_type(compression: Compression) -> &'static str {
    match compression {
        Compression::None => "application/vnd.docker.image.rootfs.diff.tar",
        Compression::Gzip => "application/vnd.docker.image.rootfs.diff.tar.gzip",
        Compression::Zstd => "application/vnd.oci.image.layer.v1.tar+zstd",
    }
}

fn required_config_diff_ids(config: &Value) -> anyhow::Result<Vec<String>> {
    let values = config
        .pointer("/rootfs/diff_ids")
        .and_then(Value::as_array)
        .context("image config missing rootfs.diff_ids")?;
    let mut diff_ids = Vec::with_capacity(values.len());
    for value in values {
        let diff_id = value
            .as_str()
            .context("image config diff ID is not a string")?;
        let Some((algorithm, encoded)) = diff_id.split_once(':') else {
            bail!("invalid image config diff ID {diff_id}");
        };
        if algorithm != "sha256"
            || encoded.len() != 64
            || !encoded
                .chars()
                .all(|character| character.is_ascii_hexdigit())
        {
            bail!("invalid sha256 image config diff ID {diff_id}");
        }
        diff_ids.push(diff_id.to_string());
    }
    Ok(diff_ids)
}

fn validate_layer_media_type(media_type: &str, compression: Compression) -> anyhow::Result<()> {
    let valid = match compression {
        Compression::None => matches!(
            media_type,
            "application/vnd.oci.image.layer.v1.tar"
                | "application/vnd.docker.image.rootfs.diff.tar"
        ),
        Compression::Gzip => matches!(
            media_type,
            "application/vnd.oci.image.layer.v1.tar+gzip"
                | "application/vnd.docker.image.rootfs.diff.tar.gzip"
        ),
        Compression::Zstd => media_type == "application/vnd.oci.image.layer.v1.tar+zstd",
    };
    if !valid {
        bail!("layer media type {media_type} does not match blob compression");
    }
    Ok(())
}

fn validate_descriptor_size(
    descriptor: &Value,
    path: &Path,
    description: &str,
) -> anyhow::Result<()> {
    let declared = descriptor
        .get("size")
        .and_then(Value::as_u64)
        .with_context(|| format!("OCI {description} descriptor missing size"))?;
    let actual = fs::metadata(path)?.len();
    if declared != actual {
        bail!("OCI {description} size mismatch: descriptor declared {declared}, found {actual}");
    }
    Ok(())
}

fn uncompressed_file_digest(path: &Path) -> anyhow::Result<String> {
    let mut reader = archive_reader(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
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
    if value.len() != 64 || !value.chars().all(|character| character.is_ascii_hexdigit()) {
        bail!("invalid sha256 OCI digest {digest}")
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
    let mut components_seen = 0_usize;
    for component in path.components() {
        match component {
            Component::Normal(value) => {
                components_seen += 1;
                if components_seen > MAX_PATH_COMPONENTS {
                    return None;
                }
                relative.push(value);
            }
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
        std::fs::write(
            image_dir.join("config.json"),
            format!(
                r#"{{"rootfs":{{"diff_ids":["sha256:{}"]}}}}"#,
                "0".repeat(64)
            ),
        )
        .unwrap();
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

    #[test]
    fn layer_budget_is_shared_across_archives() {
        let temp = tempfile::tempdir().unwrap();
        let mut paths = Vec::new();
        for name in ["one.tar", "two.tar"] {
            let path = temp.path().join(name);
            let file = std::fs::File::create(&path).unwrap();
            let mut archive = tar::Builder::new(file);
            let bytes = b"four";
            let mut header = tar::Header::new_gnu();
            header.set_path(format!("{name}.txt")).unwrap();
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            archive.append(&header, &bytes[..]).unwrap();
            archive.finish().unwrap();
            paths.push(path);
        }
        let rootfs = temp.path().join("rootfs");
        std::fs::create_dir(&rootfs).unwrap();
        let limits = TarLimits {
            max_entries: 10,
            max_unpacked_bytes: 6,
        };
        let mut budget = TarBudget::default();

        unpack_tar_with_budget(&paths[0], &rootfs, false, limits, &mut budget).unwrap();
        let error = unpack_tar_with_budget(&paths[1], &rootfs, false, limits, &mut budget)
            .unwrap_err()
            .to_string();

        assert!(error.contains("unpacked byte limit"));
    }

    #[cfg(unix)]
    #[test]
    fn unpack_tar_preserves_safe_symlink_and_rejects_escape() {
        let temp = tempfile::tempdir().unwrap();
        let safe_tar = temp.path().join("safe.tar");
        {
            let file = std::fs::File::create(&safe_tar).unwrap();
            let mut archive = tar::Builder::new(file);
            let bytes = b"tool";
            let mut file_header = tar::Header::new_gnu();
            file_header.set_path("usr/bin/tool").unwrap();
            file_header.set_size(bytes.len() as u64);
            file_header.set_cksum();
            archive.append(&file_header, &bytes[..]).unwrap();
            let mut link_header = tar::Header::new_gnu();
            link_header.set_entry_type(tar::EntryType::Symlink);
            link_header.set_path("bin/tool").unwrap();
            link_header.set_link_name("../usr/bin/tool").unwrap();
            link_header.set_size(0);
            link_header.set_cksum();
            archive.append(&link_header, std::io::empty()).unwrap();
            archive.finish().unwrap();
        }
        let rootfs = temp.path().join("rootfs");
        std::fs::create_dir(&rootfs).unwrap();
        unpack_tar(&safe_tar, &rootfs, false).unwrap();
        assert_eq!(
            std::fs::read_link(rootfs.join("bin/tool")).unwrap(),
            PathBuf::from("../usr/bin/tool")
        );

        assert!(validate_symlink_target(Path::new("bin"), Path::new("../../escape")).is_err());
    }
}
