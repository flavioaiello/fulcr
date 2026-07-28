use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

use anyhow::Context;
use serde::{Serialize, de::DeserializeOwned};
use tokio::fs;
use uuid::Uuid;

use crate::models::{
    BinaryAnalysis, BuildRecord, BuildStatus, FindingSeverity, Recipe, ScanFinding, ScanMode,
    ScanReport, ScanStatus, ScanSummary, VexStatement, oci_image_config_bytes,
};

const CORRUPT_RECORD_TIMESTAMP: &str = "1970-01-01T00:00:00Z";

#[derive(Debug, Clone)]
pub struct Store {
    data_dir: PathBuf,
    recipe_lock: Arc<Mutex<()>>,
    evidence_lock: Arc<Mutex<()>>,
    vex_lock: Arc<Mutex<()>>,
    recipe_index: Arc<Mutex<BTreeMap<String, Uuid>>>, // tag/digest -> id
    blob_index: Arc<Mutex<BTreeMap<String, Uuid>>>,   // recipe config digest -> id
}

impl Store {
    pub async fn open(data_dir: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let store = Self {
            data_dir: data_dir.into(),
            recipe_lock: Arc::new(Mutex::new(())),
            evidence_lock: Arc::new(Mutex::new(())),
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
        let mut recipes = Vec::new();
        let mut entries = fs::read_dir(self.recipes_dir()).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if !is_json_file(&path) {
                continue;
            }
            match fs::read(&path).await {
                Ok(bytes) => match serde_json::from_slice::<Recipe>(&bytes) {
                    Ok(recipe) => recipes.push(recipe),
                    Err(error) => tracing::error!(
                        path = %path.display(),
                        %error,
                        "ignoring corrupt recipe record while rebuilding index"
                    ),
                },
                Err(error) => tracing::error!(
                    path = %path.display(),
                    %error,
                    "ignoring unreadable recipe record while rebuilding index"
                ),
            }
        }
        recipes.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });

        let mut index = self.recipe_index.lock().await;
        let mut blobs = self.blob_index.lock().await;
        for recipe in recipes {
            index.insert(
                format!("{}:{}", recipe.name, recipe.source.revision),
                recipe.id,
            );
            index.insert(recipe.digest.clone(), recipe.id);
            if let Ok(config) = oci_image_config_bytes(&recipe) {
                blobs.insert(crate::digest::digest_bytes(&config), recipe.id);
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

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub async fn sweep_cache(&self) -> anyhow::Result<()> {
        // Build a digest -> longest TTL map from the latest build records, so cached
        // artifacts honor the per-recipe retention policy instead of a blanket 24h.
        let mut ttl_per_digest: BTreeMap<String, u64> = BTreeMap::new();
        let mut recipe_entries = fs::read_dir(self.recipes_dir()).await?;
        while let Some(entry) = recipe_entries.next_entry().await? {
            if !is_json_file(&entry.path()) {
                continue;
            }
            let path = entry.path();
            let bytes = match fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "skipping unreadable recipe during cache sweep");
                    continue;
                }
            };
            let recipe = match serde_json::from_slice::<Recipe>(&bytes) {
                Ok(recipe) => recipe,
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "skipping corrupt recipe during cache sweep");
                    continue;
                }
            };
            let ttl = recipe.policy.cache_ttl_seconds;
            let builds = self.list_builds(recipe.id).await?;
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

        let mut entries = match fs::read_dir(self.cache_dir()).await {
            Ok(entries) => entries,
            Err(_) => return Ok(()),
        };
        while let Some(entry) = entries.next_entry().await? {
            let file_name = entry.file_name().to_string_lossy().into_owned();
            // Default fallback for stray cache files we cannot associate to a recipe.
            let ttl = ttl_per_digest.get(&file_name).copied().unwrap_or(900);
            if ttl == 0 {
                continue;
            }
            if let Ok(metadata) = entry.metadata().await
                && let Ok(modified) = metadata.modified()
                && let Ok(elapsed) = modified.elapsed()
                && elapsed.as_secs() > ttl
            {
                fs::remove_file(entry.path()).await?;
            }
        }
        Ok(())
    }

    pub async fn save_recipe(&self, recipe: &Recipe) -> anyhow::Result<Recipe> {
        let _guard = self.recipe_lock.lock().await;
        let existing_id = self.recipe_index.lock().await.get(&recipe.digest).copied();
        if let Some(existing_id) = existing_id
            && let Some(existing) = self.get_recipe(existing_id).await?
        {
            return Ok(existing);
        }

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
        Ok(recipe.clone())
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
            Ok(self
                .get_recipe(id)
                .await?
                .filter(|recipe| recipe.name == name))
        } else {
            Ok(None)
        }
    }

    pub async fn get_recipe(&self, id: Uuid) -> anyhow::Result<Option<Recipe>> {
        self.read_json_optional(self.recipe_path(id)).await
    }

    pub async fn list_recipes(&self) -> anyhow::Result<Vec<Recipe>> {
        let mut recipes = Vec::new();
        let mut entries = fs::read_dir(self.recipes_dir()).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if !is_json_file(&path) {
                continue;
            }
            match fs::read(&path).await {
                Ok(bytes) => match serde_json::from_slice::<Recipe>(&bytes) {
                    Ok(recipe) => recipes.push(recipe),
                    Err(error) => tracing::error!(
                        path = %path.display(),
                        %error,
                        "ignoring corrupt recipe record"
                    ),
                },
                Err(error) => tracing::error!(
                    path = %path.display(),
                    %error,
                    "ignoring unreadable recipe record"
                ),
            }
        }
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

    pub async fn save_build_with_scan(
        &self,
        build: &BuildRecord,
        scan: &ScanReport,
    ) -> anyhow::Result<()> {
        let _guard = self.evidence_lock.lock().await;
        self.save_scan(scan).await?;
        if let Err(error) = self.save_build(build).await {
            if let Err(cleanup_error) =
                fs::remove_file(self.scan_path(scan.recipe_id, scan.id)).await
            {
                tracing::error!(
                    ?cleanup_error,
                    scan_id = %scan.id,
                    "failed to roll back scan after build persistence failure"
                );
            }
            return Err(error);
        }
        Ok(())
    }

    pub async fn list_builds(&self, recipe_id: Uuid) -> anyhow::Result<Vec<BuildRecord>> {
        let dir = self.builds_dir().join(recipe_id.to_string());
        if !dir.exists() {
            return Ok(Vec::new());
        }

        let (mut builds, corrupt_records): (Vec<BuildRecord>, _) =
            self.read_json_dir_tolerant(dir).await?;
        builds.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        if !corrupt_records.is_empty() {
            builds.push(BuildRecord {
                id: Uuid::nil(),
                recipe_id,
                recipe_digest: String::new(),
                source_scan_id: None,
                source_scan_digest: None,
                artifact_scan_id: None,
                policy_decision: None,
                status: BuildStatus::Failed,
                created_at: CORRUPT_RECORD_TIMESTAMP.to_string(),
                started_at: Some(CORRUPT_RECORD_TIMESTAMP.to_string()),
                finished_at: Some(CORRUPT_RECORD_TIMESTAMP.to_string()),
                command: Vec::new(),
                working_dir: None,
                exit_code: None,
                artifact: None,
                stdout_tail: None,
                stderr_tail: None,
                notes: vec![format!(
                    "corrupt build evidence: {}",
                    corrupt_records.join(", ")
                )],
            });
        }
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

        let (mut scans, corrupt_records): (Vec<ScanReport>, _) =
            self.read_json_dir_tolerant(dir).await?;
        scans.sort_by(|left, right| left.created_at.cmp(&right.created_at));
        if !corrupt_records.is_empty() {
            let evidence = corrupt_records.join(", ");
            scans.push(ScanReport {
                id: Uuid::nil(),
                recipe_id,
                recipe_digest: String::new(),
                created_at: CORRUPT_RECORD_TIMESTAMP.to_string(),
                scanner: "fulcr-store-integrity".to_string(),
                filesystem_digest: None,
                declared_artifact_digest: None,
                mode: ScanMode::Source,
                root: PathBuf::from("<corrupt-scan-record>"),
                image: None,
                status: ScanStatus::Failed,
                summary: ScanSummary {
                    findings_detected: 1,
                    ..Default::default()
                },
                components: Vec::new(),
                crypto: Vec::new(),
                binaries: Vec::<BinaryAnalysis>::new(),
                findings: vec![ScanFinding {
                    severity: FindingSeverity::High,
                    category: "store-corrupt-scan-record".to_string(),
                    message: "one or more persisted scan records could not be read".to_string(),
                    evidence: evidence.clone(),
                }],
                vulnerability_assessments: Vec::new(),
                sbom: serde_json::json!({
                    "error": "corrupt persisted scan evidence",
                    "records": corrupt_records
                }),
                cbom: serde_json::json!({
                    "error": "corrupt persisted scan evidence",
                    "records": evidence
                }),
            });
        }
        Ok(scans)
    }

    pub async fn get_scan(
        &self,
        recipe_id: Uuid,
        scan_id: Uuid,
    ) -> anyhow::Result<Option<ScanReport>> {
        self.read_json_optional(self.scan_path(recipe_id, scan_id))
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

    fn scan_path(&self, recipe_id: Uuid, scan_id: Uuid) -> PathBuf {
        self.scans_dir()
            .join(recipe_id.to_string())
            .join(format!("{scan_id}.json"))
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

    async fn read_json_dir_tolerant<T: DeserializeOwned>(
        &self,
        dir: PathBuf,
    ) -> anyhow::Result<(Vec<T>, Vec<String>)> {
        let mut values = Vec::new();
        let mut corrupt_records = Vec::new();
        let mut entries = fs::read_dir(&dir)
            .await
            .with_context(|| format!("reading {}", dir.display()))?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if is_json_file(&path) {
                let record_name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("unknown.json")
                    .to_string();
                match fs::read(&path).await {
                    Ok(bytes) => match serde_json::from_slice(&bytes) {
                        Ok(value) => values.push(value),
                        Err(error) => {
                            tracing::error!(path = %path.display(), %error, "corrupt JSON store record");
                            corrupt_records.push(record_name);
                        }
                    },
                    Err(error) => {
                        tracing::error!(path = %path.display(), %error, "unreadable JSON store record");
                        corrupt_records.push(record_name);
                    }
                }
            }
        }

        Ok((values, corrupt_records))
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

    #[tokio::test]
    async fn digest_lookup_is_scoped_to_recipe_name() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).await.unwrap();
        let recipe = crate::models::Recipe::new(RecipeInput {
            name: "team/service".to_string(),
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

        assert!(
            store
                .lookup_recipe("other/service", &recipe.digest)
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .lookup_recipe(&recipe.name, &recipe.digest)
                .await
                .unwrap()
                .unwrap()
                .id,
            recipe.id
        );
    }

    #[tokio::test]
    async fn duplicate_recipe_save_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).await.unwrap();
        let input = RecipeInput {
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
        };
        let first = Recipe::new(input.clone()).unwrap();
        let second = Recipe::new(input).unwrap();

        let saved_first = store.save_recipe(&first).await.unwrap();
        let saved_second = store.save_recipe(&second).await.unwrap();

        assert_eq!(saved_first.id, saved_second.id);
        assert_eq!(store.list_recipes().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn corrupt_recipe_does_not_hide_healthy_recipes() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).await.unwrap();
        let recipe = Recipe::new(RecipeInput {
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
        fs::write(store.recipes_dir().join("corrupt.json"), b"not-json")
            .await
            .unwrap();

        let recipes = store.list_recipes().await.unwrap();

        assert_eq!(recipes.len(), 1);
        assert_eq!(recipes[0].id, recipe.id);
    }

    #[tokio::test]
    async fn sweep_cache_removes_unassociated_expired_files() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).await.unwrap();
        let cache_path = store.cache_dir().join("stray");
        fs::write(&cache_path, b"temporary").await.unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(901);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&cache_path)
            .unwrap();
        file.set_modified(old).unwrap();

        store.sweep_cache().await.unwrap();

        assert!(!cache_path.exists());
    }

    #[tokio::test]
    async fn corrupt_build_and_scan_records_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).await.unwrap();
        let recipe_id = Uuid::new_v4();
        let build_dir = store.builds_dir().join(recipe_id.to_string());
        let scan_dir = store.scans_dir().join(recipe_id.to_string());
        fs::create_dir_all(&build_dir).await.unwrap();
        fs::create_dir_all(&scan_dir).await.unwrap();
        fs::write(build_dir.join("corrupt.json"), b"not-json")
            .await
            .unwrap();
        fs::write(scan_dir.join("corrupt.json"), b"not-json")
            .await
            .unwrap();

        let builds = store.list_builds(recipe_id).await.unwrap();
        let scans = store.list_scans(recipe_id).await.unwrap();

        assert!(matches!(builds.last().unwrap().status, BuildStatus::Failed));
        assert!(matches!(scans.last().unwrap().status, ScanStatus::Failed));
        assert!(scans.last().unwrap().findings.iter().any(|finding| {
            finding.severity == FindingSeverity::High
                && finding.category == "store-corrupt-scan-record"
        }));
    }
}
