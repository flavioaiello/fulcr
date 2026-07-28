use serde_json::{Value, json};
use std::collections::BTreeSet;

use crate::{
    digest::digest_json,
    models::{
        BuildRecord, BuildStatus, FindingSeverity, Recipe, ScanFinding, ScanReport, VexStatement,
    },
};

pub fn sbom_document(recipe: &Recipe) -> Value {
    let packages: Vec<Value> = recipe
        .materials
        .iter()
        .enumerate()
        .map(|(index, material)| {
            json!({
                "name": material.name,
                "SPDXID": format!("SPDXRef-Material-{}", index + 1),
                "versionInfo": material.version.clone().unwrap_or_else(|| "NOASSERTION".to_string()),
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "checksums": [{
                    "algorithm": "SHA256",
                    "checksumValue": material.digest.strip_prefix("sha256:").unwrap_or(&material.digest)
                }],
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": material.kind.clone().unwrap_or_else(|| "material".to_string()),
                    "referenceLocator": material.name
                }]
            })
        })
        .collect();

    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": recipe.name,
        "documentNamespace": format!("urn:fulcr:sbom:{}", recipe.digest.replace(':', "-")),
        "creationInfo": {
            "created": recipe.created_at,
            "creators": ["Tool: fulcr"]
        },
        "documentDescribes": ["SPDXRef-Recipe"],
        "packages": packages,
        "annotations": [{
            "annotationType": "OTHER",
            "annotator": "Tool: fulcr",
            "annotationDate": recipe.created_at,
            "comment": "SBOM generated from source-bound recipe materials, not from a retained binary blob."
        }]
    })
}

pub fn cbom_document(recipe: &Recipe) -> Value {
    json!({
        "bomFormat": "CBOM-like",
        "specVersion": "prototype",
        "serialNumber": format!("urn:fulcr:cbom:{}", recipe.digest.replace(':', "-")),
        "metadata": {
            "component": {
                "name": recipe.name,
                "source": recipe.source.repo,
                "revision": recipe.source.revision
            }
        },
        "crypto": recipe.crypto,
        "annotations": {
            "dev.fulcr.source": "crypto inventory is bound to the recipe and source revision"
        }
    })
}

pub fn openvex_document(recipe: &Recipe, statements: &[VexStatement]) -> Value {
    let statements: Vec<Value> = statements
        .iter()
        .filter(|statement| statement.recipe_digest == recipe.digest)
        .map(|statement| {
            json!({
                "vulnerability": { "name": statement.vulnerability },
                "timestamp": statement.created_at,
                "products": [{
                    "@id": statement.product.clone().unwrap_or_else(|| format!("urn:fulcr:recipe:{}", recipe.digest))
                }],
                "subcomponents": statement.component.as_ref().map(|component| json!([{ "@id": component }])),
                "status": statement.status,
                "justification": statement.justification,
                "impact_statement": statement.detail,
                "action_statement": "tracked by fulcr metadata registry",
                "x_fulcr_author": statement.author,
                "x_fulcr_expires_at": statement.expires_at,
                "x_fulcr_origin": if statement.author.as_deref() == Some("fulcr-autonomous") {
                    "autonomous"
                } else {
                    "external"
                }
            })
        })
        .collect();

    json!({
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": format!("urn:fulcr:openvex:{}", recipe.digest.replace(':', "-")),
        "author": "fulcr",
        "role": "metadata-registry",
        "timestamp": recipe.created_at,
        "version": 1,
        "statements": statements
    })
}

pub fn combined_vex_statements(
    recipe: &Recipe,
    latest_scan: Option<&ScanReport>,
    external: &[VexStatement],
) -> Vec<VexStatement> {
    let artifact_product = latest_scan
        .and_then(|scan| scan.image.as_ref())
        .and_then(|image| image.layers.first())
        .map(|layer| format!("urn:oci:blob:{}", layer.digest));
    let mut statements = latest_scan
        .into_iter()
        .flat_map(|scan| {
            let product = scan
                .image
                .as_ref()
                .and_then(|image| image.layers.first())
                .map(|layer| format!("urn:oci:blob:{}", layer.digest))
                .unwrap_or_else(|| format!("urn:fulcr:recipe:{}", recipe.digest));
            scan.vulnerability_assessments
                .iter()
                .map(move |assessment| VexStatement {
                    id: uuid::Uuid::nil(),
                    recipe_id: recipe.id,
                    recipe_digest: recipe.digest.clone(),
                    created_at: scan.created_at.clone(),
                    vulnerability: assessment.vulnerability.clone(),
                    status: assessment.status,
                    product: Some(product.clone()),
                    component: Some(assessment.component.clone()),
                    justification: Some(assessment.justification.clone()),
                    detail: Some(format!(
                        "{} Evidence: {}",
                        assessment.detail, assessment.evidence
                    )),
                    author: Some("fulcr-autonomous".to_string()),
                    expires_at: None,
                })
        })
        .collect::<Vec<_>>();
    let mut seen = BTreeSet::new();
    let mut effective_external = external
        .iter()
        .rev()
        .filter(|statement| statement.recipe_digest == recipe.digest)
        .filter(|statement| {
            seen.insert((
                statement.vulnerability.clone(),
                statement.product.clone(),
                statement.component.clone(),
            ))
        })
        .filter(|statement| {
            external_statement_is_active(recipe, statement, artifact_product.as_deref())
        })
        .cloned()
        .collect::<Vec<_>>();
    effective_external.reverse();
    for external_statement in effective_external {
        statements.retain(|autonomous| {
            autonomous.vulnerability != external_statement.vulnerability
                || autonomous.component != external_statement.component
                || (external_statement.product.is_some()
                    && autonomous.product != external_statement.product)
        });
        statements.push(external_statement);
    }
    statements
}

fn external_statement_is_active(
    recipe: &Recipe,
    statement: &VexStatement,
    artifact_product: Option<&str>,
) -> bool {
    if statement.recipe_digest != recipe.digest {
        return false;
    }
    match statement.status {
        crate::models::VexStatus::Affected | crate::models::VexStatus::UnderInvestigation => true,
        crate::models::VexStatus::Fixed => false,
        crate::models::VexStatus::NotAffected => {
            recipe.policy.allow_external_vex_overrides
                && statement.product.as_deref() == artifact_product
                && statement
                    .component
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                && statement
                    .justification
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                && statement
                    .detail
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                && statement
                    .author
                    .as_deref()
                    .is_some_and(|value| !value.is_empty())
                && statement.expires_at.as_deref().is_some_and(|expires_at| {
                    time::OffsetDateTime::parse(
                        expires_at,
                        &time::format_description::well_known::Rfc3339,
                    )
                    .is_ok_and(|expires_at| expires_at > time::OffsetDateTime::now_utc())
                })
        }
    }
}

pub fn attestation_document(
    recipe: &Recipe,
    latest_build: Option<&BuildRecord>,
    vex: &[VexStatement],
) -> anyhow::Result<Value> {
    let sbom = sbom_document(recipe);
    let cbom = cbom_document(recipe);
    let openvex = openvex_document(recipe, vex);

    Ok(json!({
        "predicateType": "https://fulcr.dev/attestation/source-bound-build/v0.1",
        "subject": {
            "name": recipe.name,
            "digest": { "sha256": recipe.digest.strip_prefix("sha256:").unwrap_or(&recipe.digest) }
        },
        "predicate": {
            "source": stable_source(recipe),
            "builder": recipe.builder,
            "build": recipe.build,
            "materials": recipe.materials,
            "policy": recipe.policy,
            "binaryRetention": if recipe.policy.retain_artifact { "selective" } else { "ephemeral" },
            "latestBuild": latest_build.map(stable_build_evidence),
            "metadata": {
                "sbomDigest": digest_json(&sbom)?,
                "cbomDigest": digest_json(&cbom)?,
                "openvexDigest": digest_json(&openvex)?
            }
        }
    }))
}

pub fn slsa_provenance_document(
    recipe: &Recipe,
    latest_build: Option<&BuildRecord>,
    latest_scan: Option<&ScanReport>,
    vex: &[VexStatement],
) -> anyhow::Result<Value> {
    let sbom = latest_scan
        .map(|scan| scan.sbom.clone())
        .unwrap_or_else(|| sbom_document(recipe));
    let cbom = latest_scan
        .map(|scan| scan.cbom.clone())
        .unwrap_or_else(|| cbom_document(recipe));
    let openvex = openvex_document(recipe, vex);
    let policy_findings = slsa_policy_findings(recipe, latest_build, latest_scan);
    let policy_outcome = if policy_findings.is_empty() {
        "satisfied"
    } else {
        "denied"
    };

    let mut subjects = vec![json!({
        "name": recipe.name,
        "digest": { "sha256": sha256_value(&recipe.digest) }
    })];
    if let Some(artifact) = latest_build.and_then(|build| build.artifact.as_ref()) {
        subjects.push(json!({
            "name": recipe
                .build
                .artifact
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| recipe.name.clone()),
            "digest": { "sha256": sha256_value(&artifact.digest) }
        }));
    }

    let mut resolved_dependencies = vec![json!({
        "uri": recipe.source.repo,
        "digest": { "gitCommit": recipe.source.revision },
        "name": "source"
    })];
    if let Some(builder_digest) = &recipe.builder.digest {
        resolved_dependencies.push(json!({
            "uri": recipe.builder.name.clone().unwrap_or_else(|| "urn:fulcr:builder".to_string()),
            "digest": { "sha256": sha256_value(builder_digest) },
            "name": "builder"
        }));
    }
    for material in &recipe.materials {
        resolved_dependencies.push(json!({
            "uri": material.name,
            "digest": { "sha256": sha256_value(&material.digest) },
            "name": material.name,
            "annotations": {
                "dev.fulcr.kind": material.kind,
                "dev.fulcr.version": material.version
            }
        }));
    }
    if let Some(scan) = latest_scan {
        resolved_dependencies.push(json!({
            "uri": format!("urn:fulcr:scan:{}", scan.id),
            "digest": { "sha256": sha256_value(&scan_evidence_digest(scan)?) },
            "name": "latest-scan-report"
        }));
    }
    if let Some(build) = latest_build
        && let (Some(scan_id), Some(scan_digest)) =
            (build.source_scan_id, build.source_scan_digest.as_deref())
    {
        resolved_dependencies.push(json!({
            "uri": format!("urn:fulcr:scan:{scan_id}"),
            "digest": { "sha256": sha256_value(scan_digest) },
            "name": "source-scan-report"
        }));
    }

    let invocation_id = latest_build
        .map(|build| build.id.to_string())
        .unwrap_or_else(|| recipe.id.to_string());
    let started_on = latest_build
        .and_then(|build| build.started_at.clone())
        .unwrap_or_else(|| recipe.created_at.clone());
    let finished_on = latest_build
        .and_then(|build| build.finished_at.clone())
        .unwrap_or_else(|| recipe.created_at.clone());

    Ok(json!({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://fulcr.dev/build/source-bound/v0.1",
                "externalParameters": {
                    "source": stable_source(recipe),
                    "build": recipe.build,
                    "annotations": recipe.annotations
                },
                "internalParameters": {
                    "recipeDigest": recipe.digest,
                    "binaryRetention": if recipe.policy.retain_artifact { "selective" } else { "ephemeral" },
                    "durableMetadataOnly": recipe.policy.durable_metadata_only,
                    "provenancePolicy": {
                        "id": "https://fulcr.dev/policy/slsa-tight/v0.1",
                        "sourceRevision": "immutable-git-commit-required",
                        "builderDigest": "required",
                        "materialDigests": "required-sha256",
                        "scanEvidence": "required-for-materialization",
                        "buildEvidence": "must-match-recipe-when-present"
                    }
                },
                "resolvedDependencies": resolved_dependencies
            },
            "runDetails": {
                "builder": {
                    "id": recipe.builder.name.clone().unwrap_or_else(|| format!("urn:fulcr:builder:{:?}", recipe.builder.kind)),
                    "builderDependencies": recipe.builder.digest.as_ref().map(|digest| json!([{
                        "uri": recipe.builder.name.clone().unwrap_or_else(|| "urn:fulcr:builder".to_string()),
                        "digest": { "sha256": sha256_value(digest) }
                    }]))
                },
                "metadata": {
                    "invocationId": invocation_id,
                    "startedOn": started_on,
                    "finishedOn": finished_on,
                    "fulcrSlsaPolicy": {
                        "outcome": policy_outcome,
                        "findings": policy_findings
                    }
                },
                "byproducts": [
                    {
                        "uri": "urn:fulcr:sbom",
                        "digest": { "sha256": sha256_value(&digest_json(&sbom)?) }
                    },
                    {
                        "uri": "urn:fulcr:cbom",
                        "digest": { "sha256": sha256_value(&digest_json(&cbom)?) }
                    },
                    {
                        "uri": "urn:fulcr:openvex",
                        "digest": { "sha256": sha256_value(&digest_json(&openvex)?) }
                    }
                ]
            }
        }
    }))
}

fn stable_source(recipe: &Recipe) -> Value {
    json!({
        "repo": recipe.source.repo,
        "revision": recipe.source.revision
    })
}

fn stable_build_evidence(build: &BuildRecord) -> Value {
    let mut value = serde_json::to_value(build).expect("BuildRecord serialization should succeed");
    if let Some(object) = value.as_object_mut() {
        object.remove("working_dir");
        if let Some(artifact) = object.get_mut("artifact").and_then(Value::as_object_mut) {
            artifact.remove("path");
        }
    }
    value
}

pub fn scan_evidence_digest(scan: &ScanReport) -> anyhow::Result<String> {
    let mut value = serde_json::to_value(scan)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("root");
        if let Some(image) = object.get_mut("image").and_then(Value::as_object_mut) {
            image.remove("archive");
        }
    }
    digest_json(&value)
}

pub fn slsa_policy_findings(
    recipe: &Recipe,
    latest_build: Option<&BuildRecord>,
    latest_scan: Option<&ScanReport>,
) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    if !is_immutable_revision(&recipe.source.revision) {
        findings.push(slsa_finding(
            "slsa-unpinned-source",
            "source revision is not an immutable full git commit hash",
            format!("source.revision={}", recipe.source.revision),
        ));
    }

    match recipe.builder.digest.as_deref() {
        Some(digest) if is_sha256_digest(digest) => {}
        Some(digest) => findings.push(slsa_finding(
            "slsa-unpinned-builder",
            "builder digest is present but is not a sha256 digest",
            format!("builder.digest={digest}"),
        )),
        None => findings.push(slsa_finding(
            "slsa-unpinned-builder",
            "builder digest is required for tightened SLSA posture",
            "builder.digest".to_string(),
        )),
    }

    for material in &recipe.materials {
        if !is_sha256_digest(&material.digest) {
            findings.push(slsa_finding(
                "slsa-undigested-material",
                format!("material {} does not have a sha256 digest", material.name),
                format!("materials.{}", material.name),
            ));
        }
    }

    if !recipe.policy.durable_metadata_only {
        findings.push(slsa_finding(
            "slsa-durable-metadata-disabled",
            "durable metadata-only retention is disabled for this recipe",
            "policy.durable_metadata_only".to_string(),
        ));
    }

    match latest_scan {
        Some(scan) if scan.recipe_digest == recipe.digest => {}
        Some(scan) => findings.push(slsa_finding(
            "slsa-stale-scan-evidence",
            "latest scan evidence was produced for a different recipe digest",
            format!("scan.{}", scan.id),
        )),
        None => findings.push(slsa_finding(
            "slsa-missing-scan-evidence",
            "latest scan evidence is required before materialization",
            "latest-scan-report".to_string(),
        )),
    }

    if let Some(build) = latest_build {
        if build.recipe_digest != recipe.digest {
            findings.push(slsa_finding(
                "slsa-stale-build-evidence",
                "latest build evidence was produced for a different recipe digest",
                format!("build.{}", build.id),
            ));
        }
        if matches!(build.status, BuildStatus::Failed) {
            findings.push(slsa_finding(
                "slsa-build-failed",
                "latest build evidence records a failed build",
                format!("build.{}", build.id),
            ));
        }
        if build.started_at.is_none() || build.finished_at.is_none() {
            findings.push(slsa_finding(
                "slsa-incomplete-build-timestamps",
                "latest build evidence lacks start or finish timestamps",
                format!("build.{}", build.id),
            ));
        }
        if build.source_scan_id.is_none()
            || !build
                .source_scan_digest
                .as_deref()
                .is_some_and(is_sha256_digest)
        {
            findings.push(slsa_finding(
                "slsa-missing-source-scan-binding",
                "build evidence is not bound to a canonical source scan digest",
                format!("build.{}", build.id),
            ));
        }
        if recipe.build.artifact.is_some()
            && matches!(build.status, BuildStatus::Succeeded)
            && build.artifact.is_none()
        {
            findings.push(slsa_finding(
                "slsa-artifact-not-fingerprinted",
                "declared artifact was not fingerprinted by the latest successful build",
                format!("build.{}", build.id),
            ));
        }
        if let Some(artifact) = build
            .artifact
            .as_ref()
            .filter(|_| matches!(build.status, BuildStatus::Succeeded))
        {
            let artifact_was_scanned = latest_scan
                .and_then(|scan| scan.image.as_ref())
                .is_some_and(|image| {
                    image
                        .layers
                        .iter()
                        .any(|layer| layer.digest == artifact.digest)
                });
            if !artifact_was_scanned {
                findings.push(slsa_finding(
                    "slsa-unscanned-artifact",
                    "latest successful artifact lacks scan evidence bound to its layer digest",
                    format!("artifact.{}", artifact.digest),
                ));
            }
        }
    }

    findings
}

fn slsa_finding(
    category: impl Into<String>,
    message: impl Into<String>,
    evidence: impl Into<String>,
) -> ScanFinding {
    ScanFinding {
        severity: FindingSeverity::High,
        category: category.into(),
        message: message.into(),
        evidence: evidence.into(),
    }
}

fn is_immutable_revision(revision: &str) -> bool {
    matches!(revision.len(), 40 | 64)
        && revision
            .chars()
            .all(|character| character.is_ascii_hexdigit())
}

fn is_sha256_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|value| {
        value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
    })
}

fn sha256_value(digest: &str) -> &str {
    digest.strip_prefix("sha256:").unwrap_or(digest)
}

#[cfg(test)]
mod tests {
    use crate::models::{
        BuilderKind, BuilderRef, ImageLayerMetadata, ImageScanMetadata, Material, Recipe,
        RecipeInput, ScanMode, ScanReport, ScanStatus, ScanSummary, SourceRef, VexStatement,
        VexStatus, VulnerabilityAssessment, timestamp,
    };

    use super::*;

    #[test]
    fn sbom_contains_recipe_materials() {
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "abc123".to_string(),
                path: None,
            },
            builder: BuilderRef {
                kind: BuilderKind::Containerfile,
                name: None,
                digest: Some("sha256:1234".to_string()),
            },
            build: Default::default(),
            materials: vec![Material {
                name: "Cargo.lock".to_string(),
                digest: "sha256:abcd".to_string(),
                kind: Some("lockfile".to_string()),
                version: None,
            }],
            crypto: Vec::new(),
            policy: Default::default(),
            annotations: Default::default(),
        })
        .unwrap();

        let sbom = sbom_document(&recipe);
        assert_eq!(sbom["packages"][0]["name"], "Cargo.lock");
    }

    #[test]
    fn slsa_document_uses_standard_predicate() {
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "abc123".to_string(),
                path: None,
            },
            builder: BuilderRef {
                kind: BuilderKind::Containerfile,
                name: Some("builder".to_string()),
                digest: Some("sha256:1234".to_string()),
            },
            build: Default::default(),
            materials: Vec::new(),
            crypto: Vec::new(),
            policy: Default::default(),
            annotations: Default::default(),
        })
        .unwrap();

        let slsa = slsa_provenance_document(&recipe, None, None, &[]).unwrap();
        assert_eq!(slsa["_type"], "https://in-toto.io/Statement/v1");
        assert_eq!(slsa["predicateType"], "https://slsa.dev/provenance/v1");
        assert_eq!(
            slsa["predicate"]["runDetails"]["metadata"]["fulcrSlsaPolicy"]["outcome"],
            "denied"
        );
        assert!(
            slsa["predicate"]["runDetails"]["metadata"]["fulcrSlsaPolicy"]["findings"]
                .as_array()
                .is_some_and(|findings| !findings.is_empty())
        );
    }

    #[test]
    fn openvex_document_filters_stale_recipe_digest_statements() {
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "abc123".to_string(),
                path: None,
            },
            builder: BuilderRef {
                kind: BuilderKind::Containerfile,
                name: Some("builder".to_string()),
                digest: Some("sha256:1234".to_string()),
            },
            build: Default::default(),
            materials: Vec::new(),
            crypto: Vec::new(),
            policy: Default::default(),
            annotations: Default::default(),
        })
        .unwrap();

        let openvex = openvex_document(
            &recipe,
            &[
                VexStatement {
                    id: uuid::Uuid::new_v4(),
                    recipe_id: recipe.id,
                    recipe_digest: recipe.digest.clone(),
                    created_at: timestamp(),
                    vulnerability: "CVE-2026-0001".to_string(),
                    status: VexStatus::NotAffected,
                    product: None,
                    component: None,
                    justification: None,
                    detail: None,
                    author: None,
                    expires_at: None,
                },
                VexStatement {
                    id: uuid::Uuid::new_v4(),
                    recipe_id: recipe.id,
                    recipe_digest: "sha256:stale".to_string(),
                    created_at: timestamp(),
                    vulnerability: "CVE-2026-0002".to_string(),
                    status: VexStatus::Affected,
                    product: None,
                    component: None,
                    justification: None,
                    detail: None,
                    author: None,
                    expires_at: None,
                },
            ],
        );

        let statements = openvex["statements"].as_array().unwrap();
        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0]["vulnerability"]["name"], "CVE-2026-0001");
    }

    #[test]
    fn openvex_includes_autonomous_artifact_assessments() {
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: None,
            },
            builder: BuilderRef {
                kind: BuilderKind::Script,
                name: Some("builder".to_string()),
                digest: Some(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                ),
            },
            build: Default::default(),
            materials: Vec::new(),
            crypto: Vec::new(),
            policy: Default::default(),
            annotations: Default::default(),
        })
        .unwrap();
        let layer_digest = format!("sha256:{}", "a".repeat(64));
        let scan = ScanReport {
            id: uuid::Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            created_at: timestamp(),
            scanner: "test".to_string(),
            filesystem_digest: None,
            declared_artifact_digest: None,
            mode: ScanMode::Filesystem,
            root: std::path::PathBuf::from("rootfs"),
            image: Some(ImageScanMetadata {
                kind: "oci-layer-artifact".to_string(),
                archive: std::path::PathBuf::from("layer.tar"),
                manifest_digest: None,
                config_digest: None,
                tags: Vec::new(),
                layers: vec![ImageLayerMetadata {
                    digest: layer_digest.clone(),
                    diff_id: Some(layer_digest.clone()),
                    media_type: Some("application/vnd.oci.image.layer.v1.tar".to_string()),
                    size: 1024,
                }],
            }),
            status: ScanStatus::CompletedWithFindings,
            summary: ScanSummary::default(),
            components: Vec::new(),
            crypto: Vec::new(),
            binaries: Vec::new(),
            findings: Vec::new(),
            vulnerability_assessments: vec![VulnerabilityAssessment {
                vulnerability: "CVE-2026-0001".to_string(),
                status: VexStatus::Fixed,
                component: "openssl".to_string(),
                justification: "component_fixed_version".to_string(),
                detail: "artifact contains a clean fixed version".to_string(),
                evidence: "var/lib/dpkg/status#openssl".to_string(),
            }],
            sbom: json!({}),
            cbom: json!({}),
        };

        let statements = combined_vex_statements(&recipe, Some(&scan), &[]);
        let openvex = openvex_document(&recipe, &statements);
        let statement = &openvex["statements"][0];

        assert_eq!(statement["status"], "fixed");
        assert_eq!(statement["x_fulcr_origin"], "autonomous");
        assert_eq!(statement["x_fulcr_author"], "fulcr-autonomous");
        assert_eq!(
            statement["products"][0]["@id"],
            format!("urn:oci:blob:{layer_digest}")
        );
        assert!(
            statement["impact_statement"]
                .as_str()
                .is_some_and(|detail| detail.contains("var/lib/dpkg/status#openssl"))
        );
    }

    #[test]
    fn combined_vex_omits_expired_external_not_affected() {
        let policy = crate::models::RetentionPolicy {
            allow_external_vex_overrides: true,
            ..Default::default()
        };
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: None,
            },
            builder: BuilderRef {
                kind: BuilderKind::Script,
                name: Some("builder".to_string()),
                digest: Some(format!("sha256:{}", "b".repeat(64))),
            },
            build: Default::default(),
            materials: Vec::new(),
            crypto: Vec::new(),
            policy,
            annotations: Default::default(),
        })
        .unwrap();
        let layer_digest = format!("sha256:{}", "a".repeat(64));
        let mut scan = empty_metadata_scan(&recipe);
        scan.image = Some(ImageScanMetadata {
            kind: "oci-layer-artifact".to_string(),
            archive: std::path::PathBuf::from("layer.tar"),
            manifest_digest: None,
            config_digest: None,
            tags: Vec::new(),
            layers: vec![ImageLayerMetadata {
                digest: layer_digest.clone(),
                diff_id: Some(layer_digest.clone()),
                media_type: Some("application/vnd.oci.image.layer.v1.tar".to_string()),
                size: 1024,
            }],
        });
        let expired = VexStatement {
            id: uuid::Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            created_at: timestamp(),
            vulnerability: "CVE-2026-0001".to_string(),
            status: VexStatus::NotAffected,
            product: Some(format!("urn:oci:blob:{layer_digest}")),
            component: Some("openssl".to_string()),
            justification: Some("external_exception".to_string()),
            detail: Some("expired".to_string()),
            author: Some("security@example.invalid".to_string()),
            expires_at: Some("2000-01-01T00:00:00Z".to_string()),
        };

        assert!(combined_vex_statements(&recipe, Some(&scan), &[expired]).is_empty());
    }

    #[test]
    fn combined_vex_external_exception_supersedes_inconclusive_autonomous_statement() {
        let policy = crate::models::RetentionPolicy {
            allow_external_vex_overrides: true,
            ..Default::default()
        };
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: None,
            },
            builder: BuilderRef {
                kind: BuilderKind::Script,
                name: Some("builder".to_string()),
                digest: Some(format!("sha256:{}", "b".repeat(64))),
            },
            build: Default::default(),
            materials: Vec::new(),
            crypto: Vec::new(),
            policy,
            annotations: Default::default(),
        })
        .unwrap();
        let layer_digest = format!("sha256:{}", "a".repeat(64));
        let product = format!("urn:oci:blob:{layer_digest}");
        let mut scan = empty_metadata_scan(&recipe);
        scan.image = Some(ImageScanMetadata {
            kind: "oci-layer-artifact".to_string(),
            archive: std::path::PathBuf::from("layer.tar"),
            manifest_digest: None,
            config_digest: None,
            tags: Vec::new(),
            layers: vec![ImageLayerMetadata {
                digest: layer_digest.clone(),
                diff_id: Some(layer_digest),
                media_type: Some("application/vnd.oci.image.layer.v1.tar".to_string()),
                size: 1024,
            }],
        });
        scan.vulnerability_assessments
            .push(VulnerabilityAssessment {
                vulnerability: "CVE-2026-0001".to_string(),
                status: VexStatus::UnderInvestigation,
                component: "openssl".to_string(),
                justification: "artifact_exploitability_inconclusive".to_string(),
                detail: "machine evidence is inconclusive".to_string(),
                evidence: "var/lib/dpkg/status#openssl".to_string(),
            });
        let external = VexStatement {
            id: uuid::Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            created_at: timestamp(),
            vulnerability: "CVE-2026-0001".to_string(),
            status: VexStatus::NotAffected,
            product: Some(product),
            component: Some("openssl".to_string()),
            justification: Some("vulnerable_code_not_present".to_string()),
            detail: Some("external artifact analysis".to_string()),
            author: Some("security@example.invalid".to_string()),
            expires_at: Some("2999-01-01T00:00:00Z".to_string()),
        };

        let statements = combined_vex_statements(&recipe, Some(&scan), &[external]);

        assert_eq!(statements.len(), 1);
        assert_eq!(statements[0].status, VexStatus::NotAffected);
        assert_eq!(
            statements[0].author.as_deref(),
            Some("security@example.invalid")
        );
    }

    fn empty_metadata_scan(recipe: &Recipe) -> ScanReport {
        ScanReport {
            id: uuid::Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            created_at: timestamp(),
            scanner: "test".to_string(),
            filesystem_digest: None,
            declared_artifact_digest: None,
            mode: ScanMode::Filesystem,
            root: std::path::PathBuf::from("rootfs"),
            image: None,
            status: ScanStatus::Completed,
            summary: ScanSummary::default(),
            components: Vec::new(),
            crypto: Vec::new(),
            binaries: Vec::new(),
            findings: Vec::new(),
            vulnerability_assessments: Vec::new(),
            sbom: json!({}),
            cbom: json!({}),
        }
    }

    #[test]
    fn scan_evidence_digest_ignores_local_root_path() {
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: None,
            },
            builder: BuilderRef {
                kind: BuilderKind::Script,
                name: Some("builder".to_string()),
                digest: Some(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                ),
            },
            build: Default::default(),
            materials: Vec::new(),
            crypto: Vec::new(),
            policy: Default::default(),
            annotations: Default::default(),
        })
        .unwrap();
        let left = ScanReport {
            id: uuid::Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            created_at: timestamp(),
            scanner: "test".to_string(),
            filesystem_digest: None,
            declared_artifact_digest: None,
            mode: ScanMode::Source,
            root: std::path::PathBuf::from("/tmp/checkout-a"),
            image: None,
            status: ScanStatus::Completed,
            summary: ScanSummary::default(),
            components: Vec::new(),
            crypto: Vec::new(),
            binaries: Vec::new(),
            findings: Vec::new(),
            vulnerability_assessments: Vec::new(),
            sbom: json!({}),
            cbom: json!({}),
        };
        let mut right = left.clone();
        right.root = std::path::PathBuf::from("/private/work/checkout-b");

        assert_eq!(
            scan_evidence_digest(&left).unwrap(),
            scan_evidence_digest(&right).unwrap()
        );
    }
}
