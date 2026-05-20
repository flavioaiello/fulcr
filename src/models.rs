use std::{collections::BTreeMap, path::PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use uuid::Uuid;

use crate::digest::digest_json;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipeInput {
    pub name: String,
    pub source: SourceRef,
    pub builder: BuilderRef,
    #[serde(default)]
    pub build: BuildSpec,
    #[serde(default)]
    pub materials: Vec<Material>,
    #[serde(default)]
    pub crypto: Vec<CryptoMaterial>,
    #[serde(default)]
    pub policy: RetentionPolicy,
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recipe {
    pub id: Uuid,
    pub digest: String,
    pub created_at: String,
    pub name: String,
    pub source: SourceRef,
    pub builder: BuilderRef,
    pub build: BuildSpec,
    pub materials: Vec<Material>,
    pub crypto: Vec<CryptoMaterial>,
    pub policy: RetentionPolicy,
    pub annotations: BTreeMap<String, String>,
}

impl Recipe {
    pub fn new(input: RecipeInput) -> anyhow::Result<Self> {
        let digest = digest_json(&input).context("digesting recipe")?;
        Ok(Self {
            id: Uuid::new_v4(),
            digest,
            created_at: timestamp(),
            name: input.name,
            source: input.source,
            builder: input.builder,
            build: input.build,
            materials: input.materials,
            crypto: input.crypto,
            policy: input.policy,
            annotations: input.annotations,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceRef {
    pub repo: String,
    pub revision: String,
    #[serde(default)]
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuilderRef {
    pub kind: BuilderKind,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BuilderKind {
    Buildpack,
    Containerfile,
    Script,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildSpec {
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub run_command: Option<Vec<String>>,
    #[serde(default)]
    pub working_dir: Option<PathBuf>,
    #[serde(default)]
    pub artifact: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Material {
    pub name: String,
    pub digest: String,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoMaterial {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    #[serde(default = "default_true")]
    pub durable_metadata_only: bool,
    #[serde(default)]
    pub retain_artifact: bool,
    #[serde(default = "default_cache_ttl_seconds")]
    pub cache_ttl_seconds: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            durable_metadata_only: true,
            retain_artifact: false,
            cache_ttl_seconds: default_cache_ttl_seconds(),
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BuildRequest {
    #[serde(default)]
    pub execute: bool,
    #[serde(default)]
    pub cache_artifact: bool,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanRequest {
    #[serde(default)]
    pub mode: ScanMode,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub max_file_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum ScanMode {
    #[default]
    Source,
    Filesystem,
    ImageArchive,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub id: Uuid,
    pub recipe_id: Uuid,
    pub recipe_digest: String,
    pub created_at: String,
    pub scanner: String,
    #[serde(default)]
    pub mode: ScanMode,
    pub root: PathBuf,
    #[serde(default)]
    pub image: Option<ImageScanMetadata>,
    pub status: ScanStatus,
    pub summary: ScanSummary,
    pub components: Vec<ScannedComponent>,
    pub crypto: Vec<ScannedCryptoMaterial>,
    #[serde(default)]
    pub binaries: Vec<BinaryAnalysis>,
    pub findings: Vec<ScanFinding>,
    pub vex_candidates: Vec<VexCandidate>,
    pub sbom: serde_json::Value,
    pub cbom: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageScanMetadata {
    pub kind: String,
    pub archive: PathBuf,
    #[serde(default)]
    pub manifest_digest: Option<String>,
    #[serde(default)]
    pub config_digest: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub layers: Vec<ImageLayerMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageLayerMetadata {
    pub digest: String,
    #[serde(default)]
    pub media_type: Option<String>,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanStatus {
    Completed,
    CompletedWithFindings,
    Failed,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    pub files_scanned: usize,
    pub components_detected: usize,
    pub crypto_materials_detected: usize,
    #[serde(default)]
    pub binaries_analyzed: usize,
    pub findings_detected: usize,
    pub vex_candidates_detected: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedComponent {
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    pub kind: String,
    #[serde(default)]
    pub purl: Option<String>,
    #[serde(default)]
    pub digest: Option<String>,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedCryptoMaterial {
    pub name: String,
    pub kind: String,
    #[serde(default)]
    pub algorithm: Option<String>,
    #[serde(default)]
    pub purpose: Option<String>,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryAnalysis {
    pub path: String,
    pub format: String,
    #[serde(default)]
    pub architecture: Option<String>,
    pub digest: String,
    pub size: u64,
    #[serde(default)]
    pub entrypoint: Option<u64>,
    #[serde(default)]
    pub sections: Vec<String>,
    #[serde(default)]
    pub imported_libraries: Vec<String>,
    #[serde(default)]
    pub symbols: Vec<String>,
    #[serde(default)]
    pub interesting_strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanFinding {
    pub severity: FindingSeverity,
    pub category: String,
    pub message: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexCandidate {
    pub vulnerability: String,
    pub status: VexStatus,
    pub component: String,
    pub justification: String,
    pub detail: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateDecision {
    pub outcome: GateOutcome,
    pub evaluated_at: String,
    #[serde(default)]
    pub reasons: Vec<String>,
}

impl Default for GateDecision {
    fn default() -> Self {
        Self {
            outcome: GateOutcome::Denied,
            evaluated_at: timestamp(),
            reasons: vec!["gate was not evaluated".to_string()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateOutcome {
    Allowed,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRecord {
    pub id: Uuid,
    pub recipe_id: Uuid,
    pub recipe_digest: String,
    pub status: BuildStatus,
    pub created_at: String,
    #[serde(default)]
    pub started_at: Option<String>,
    #[serde(default)]
    pub finished_at: Option<String>,
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<PathBuf>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub artifact: Option<ArtifactRef>,
    #[serde(default)]
    pub stdout_tail: Option<String>,
    #[serde(default)]
    pub stderr_tail: Option<String>,
    #[serde(default)]
    pub security_anomalies: Vec<String>,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl BuildRecord {
    pub fn planned(recipe: &Recipe) -> Self {
        Self {
            id: Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            status: BuildStatus::Planned,
            created_at: timestamp(),
            started_at: None,
            finished_at: None,
            command: recipe.build.command.clone(),
            working_dir: recipe.build.working_dir.clone(),
            exit_code: None,
            artifact: None,
            stdout_tail: None,
            stderr_tail: None,
            security_anomalies: Vec::new(),
            notes: vec!["metadata-only plan; artifact can be constructed ad hoc".to_string()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildStatus {
    Planned,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub digest: String,
    pub size: u64,
    pub retained: bool,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexInput {
    pub vulnerability: String,
    pub status: VexStatus,
    /// Recipe digest the override applies to. Required so a VEX statement cannot be
    /// silently re-used against a different recipe revision; the API rejects mismatches.
    #[serde(default)]
    pub recipe_digest: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub component: Option<String>,
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VexStatement {
    pub id: Uuid,
    pub recipe_id: Uuid,
    pub recipe_digest: String,
    pub created_at: String,
    pub vulnerability: String,
    pub status: VexStatus,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(default)]
    pub component: Option<String>,
    #[serde(default)]
    pub justification: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub author: Option<String>,
}

impl VexStatement {
    pub fn new(recipe_id: Uuid, recipe_digest: String, input: VexInput) -> Self {
        Self {
            id: Uuid::new_v4(),
            recipe_id,
            recipe_digest,
            created_at: timestamp(),
            vulnerability: input.vulnerability,
            status: input.status,
            product: input.product,
            component: input.component,
            justification: input.justification,
            detail: input.detail,
            author: input.author,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VexStatus {
    NotAffected,
    Affected,
    Fixed,
    UnderInvestigation,
}

pub fn timestamp() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC3339 timestamp formatting should not fail")
}

pub fn timestamp_after_seconds(seconds: u64) -> String {
    let seconds = seconds.min(i64::MAX as u64) as i64;
    (OffsetDateTime::now_utc() + Duration::seconds(seconds))
        .format(&Rfc3339)
        .expect("RFC3339 timestamp formatting should not fail")
}

fn default_true() -> bool {
    true
}

fn default_cache_ttl_seconds() -> u64 {
    900
}
