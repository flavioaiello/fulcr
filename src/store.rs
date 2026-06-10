use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

use anyhow::Context;
use serde::{de::DeserializeOwned, Serialize};
use tokio::fs;
use uuid::Uuid;

use crate::models::{oci_image_config_bytes, BuildRecord, Recipe, ScanReport, VexStatement};

#[derive(Debug, Clone)]
pub struct Store {
    data_dir: PathBuf,
    vex_lock: Arc<Mutex<()>>,
    recipe_index: Arc<Mutex<BTreeMap<String, Uuid>>>, // tag/digest -> id
    blob_index: Arc<Mutex<BTreeMap<String, Uuid>>>,   // recipe config digest -> id
}

impl Store {
    pub async fn open(data_dir: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let store = Self {
            data_dir: data_dir.into(),
            vex_lock: Arc::new(Mutex::new(())),
            recipe_index: Arc::new(Mutex::new(BTreeMap::new())),
            blob_index: Arc::new(Mutex::new(BTreeMap::new())),
        };

        for dir in [
            store.recipes_dir(),
            store.builds_dir(),
            store.scans_dir(),
            store.vex_dir(),
            store.cache_dir(),
        ] {
            fs::create_dir_all(&dir)
                .await
                .with_context(|| format!("creating {}", dir.display()))?;
        }

        store.rebuild_index().await?;

        Ok(store)
    }

    async fn rebuild_index(&self) -> anyhow::Result<()> {
        let mut index = self.recipe_index.lock().await;
        let mut blobs = self.blob_index.lock().await;
        let mut entries = fs::read_dir(self.recipes_dir()).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if crate::store::is_json_file(&path) {
                if let Ok(bytes) = fs::read(&path).await {
                    if let Ok(recipe) = serde_json::from_slice::<Recipe>(&bytes) {
                        index.insert(
                            format!("{}:{}", recipe.name, recipe.source.revision),
                            recipe.id,
                        );
                        index.insert(recipe.digest.clone(), recipe.id);
                        if let Ok(config) = oci_image_config_bytes(&recipe) {
                            blobs.insert(crate::digest::digest_bytes(&config), recipe.id);
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn lookup_blob_recipe(&self, digest: &str) -> Option<Uuid> {
        self.blob_index.lock().await.get(digest).copied()
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.data_dir.join("cache")
    }

    pub async fn sweep_cache(&self) -> anyhow::Result<()> {
        // Build a digest -> longest TTL map from the latest build records, so cached
        // artifacts honor the per-recipe retention policy instead of a blanket 24h.
        let mut ttl_per_digest: BTreeMap<String, u64> = BTreeMap::new();
        if let Ok(mut recipe_entries) = fs::read_dir(self.recipes_dir()).await {
            while let Some(entry) = recipe_entries.next_entry().await.unwrap_or(None) {
                if !is_json_file(&entry.path()) {
                    continue;
                }
                let Ok(bytes) = fs::read(entry.path()).await else {
                    continue;
                };
                let Ok(recipe) = serde_json::from_slice::<Recipe>(&bytes) else {
                    continue;
                };
                let ttl = recipe.policy.cache_ttl_seconds;
                let builds = self.list_builds(recipe.id).await.unwrap_or_default();
                for build in builds {
                    if let Some(artifact) = build.artifact.as_ref() {
                        let entry = ttl_per_digest
                            .entry(crate::digest::cache_file_name(&artifact.digest))
                            .or_insert(0);
                        if ttl > *entry {
                            *entry = ttl;
                        }
                    }
                }
            }
        }

        let mut entries = match fs::read_dir(self.cache_dir()).await {
            Ok(entries) => entries,
            Err(_) => return Ok(()),
        };
        while let Some(entry) = entries.next_entry().await.unwrap_or(None) {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            // Default fallback for stray cache files we cannot associate to a recipe.
            let ttl = ttl_per_digest.get(&file_name).copied().unwrap_or(900);
            if ttl == 0 {
                continue; // retention disabled => keep forever
            }
            if let Ok(metadata) = entry.metadata().await {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(elapsed) = modified.elapsed() {
                        if elapsed.as_secs() > ttl {
                            let _ = fs::remove_file(entry.path()).await;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn save_recipe(&self, recipe: &Recipe) -> anyhow::Result<()> {
        self.write_json(self.recipe_path(recipe.id), recipe).await?;
        let mut index = self.recipe_index.lock().await;
        index.insert(
            format!("{}:{}", recipe.name, recipe.source.revision),
            recipe.id,
        );
        index.insert(recipe.digest.clone(), recipe.id);
        if let Ok(config) = oci_image_config_bytes(recipe) {
            self.blob_index
                .lock()
                .await
                .insert(crate::digest::digest_bytes(&config), recipe.id);
        }
        Ok(())
    }

    pub async fn lookup_recipe(
        &self,
        name: &str,
        reference: &str,
    ) -> anyhow::Result<Option<Recipe>> {
        let id_opt = {
            let index = self.recipe_index.lock().await;
            index
                .get(&format!("{}:{}", name, reference))
                .or_else(|| index.get(reference))
                .copied()
        };

        if let Some(id) = id_opt {
            self.get_recipe(id).await
        } else {
            Ok(None)
        }
    }

    pub async fn get_recipe(&self, id: Uuid) -> anyhow::Result<Option<Recipe>> {
        self.read_json_optional(self.recipe_path(id)).await
    }

    pub async fn list_recipes(&self) -> anyhow::Result<Vec<Recipe>> {
        let mut recipes: Vec<Recipe> = self.read_json_dir(self.recipes_dir()).await?;
        recipes.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        Ok(recipes)
    }

    pub async fn save_build(&self, build: &BuildRecord) -> anyhow::Result<()> {
        let dir = self.builds_dir().join(build.recipe_id.to_string());
        fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("creating {}", dir.display()))?;
        self.write_json(dir.join(format!("{}.json", build.id)), build)
            .await
    }

    pub async fn list_builds(&self, recipe_id: Uuid) -> anyhow::Result<Vec<BuildRecord>> {
        let dir = self.builds_dir().join(recipe_id.to_string());
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut builds: Vec<BuildRecord> = self.read_json_dir(dir).await?;
        builds.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        Ok(builds)
    }

    pub async fn save_scan(&self, scan: &ScanReport) -> anyhow::Result<()> {
        let dir = self.scans_dir().join(scan.recipe_id.to_string());
        fs::create_dir_all(&dir)
            .await
            .with_context(|| format!("creating {}", dir.display()))?;
        self.write_json(dir.join(format!("{}.json", scan.id)), scan)
            .await
    }

    pub async fn list_scans(&self, recipe_id: Uuid) -> anyhow::Result<Vec<ScanReport>> {
        let dir = self.scans_dir().join(recipe_id.to_string());
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let mut scans: Vec<ScanReport> = self.read_json_dir(dir).await?;
        scans.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        Ok(scans)
    }

    pub async fn get_scan(
        &self,
        recipe_id: Uuid,
        scan_id: Uuid,
    ) -> anyhow::Result<Option<ScanReport>> {
        self.read_json_optional(
            self.scans_dir()
                .join(recipe_id.to_string())
                .join(format!("{scan_id}.json")),
        )
        .await
    }

    pub async fn latest_scan(&self, recipe_id: Uuid) -> anyhow::Result<Option<ScanReport>> {
        Ok(self.list_scans(recipe_id).await?.pop())
    }

    pub async fn save_vex_statement(
        &self,
        statement: &VexStatement,
    ) -> anyhow::Result<Vec<VexStatement>> {
        let _guard = self.vex_lock.lock().await;
        let mut statements = self.list_vex(statement.recipe_id).await?;
        statements.push(statement.clone());
        self.write_json(self.vex_path(statement.recipe_id), &statements)
            .await?;
        Ok(statements)
    }

    pub async fn list_vex(&self, recipe_id: Uuid) -> anyhow::Result<Vec<VexStatement>> {
        Ok(self
            .read_json_optional(self.vex_path(recipe_id))
            .await?
            .unwrap_or_default())
    }

    fn recipes_dir(&self) -> PathBuf {
        self.data_dir.join("recipes")
    }

    fn builds_dir(&self) -> PathBuf {
        self.data_dir.join("builds")
    }

    fn scans_dir(&self) -> PathBuf {
        self.data_dir.join("scans")
    }

    fn vex_dir(&self) -> PathBuf {
        self.data_dir.join("vex")
    }

    fn recipe_path(&self, id: Uuid) -> PathBuf {
        self.recipes_dir().join(format!("{id}.json"))
    }

    fn vex_path(&self, recipe_id: Uuid) -> PathBuf {
        self.vex_dir().join(format!("{recipe_id}.json"))
    }

    async fn write_json<T: Serialize>(&self, path: PathBuf, value: &T) -> anyhow::Result<()> {
        let bytes = serde_json::to_vec_pretty(value).context("serializing json store value")?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, bytes)
            .await
            .with_context(|| format!("writing {}", tmp.display()))?;
        fs::rename(&tmp, &path)
            .await
            .with_context(|| format!("renaming {} to {}", tmp.display(), path.display()))?;
        Ok(())
    }

    async fn read_json_optional<T: DeserializeOwned>(
        &self,
        path: PathBuf,
    ) -> anyhow::Result<Option<T>> {
        match fs::read(&path).await {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes)
                    .with_context(|| format!("parsing {}", path.display()))?,
            )),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
        }
    }

    async fn read_json_dir<T: DeserializeOwned>(&self, dir: PathBuf) -> anyhow::Result<Vec<T>> {
        let mut values = Vec::new();
        let mut entries = fs::read_dir(&dir)
            .await
            .with_context(|| format!("reading {}", dir.display()))?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if is_json_file(&path) {
                let bytes = fs::read(&path)
                    .await
                    .with_context(|| format!("reading {}", path.display()))?;
                values.push(
                    serde_json::from_slice(&bytes)
                        .with_context(|| format!("parsing {}", path.display()))?,
                );
            }
        }

        Ok(values)
    }
}

fn is_json_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == "json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BuilderKind, BuilderRef, RecipeInput, SourceRef};

    #[tokio::test]
    async fn recipes_round_trip() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).await.unwrap();
        let recipe = crate::models::Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "abc123".to_string(),
                path: None,
            },
            builder: BuilderRef {
                kind: BuilderKind::Script,
                name: Some("local".to_string()),
                digest: None,
            },
            build: Default::default(),
            materials: Vec::new(),
            crypto: Vec::new(),
            policy: Default::default(),
            annotations: Default::default(),
        })
        .unwrap();

        store.save_recipe(&recipe).await.unwrap();
        assert_eq!(
            store.get_recipe(recipe.id).await.unwrap().unwrap().digest,
            recipe.digest
        );
    }
}
