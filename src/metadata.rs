use serde_json::{json, Value};

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
                "action_statement": "tracked by fulcr metadata registry"
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
            "source": recipe.source,
            "builder": recipe.builder,
            "build": recipe.build,
            "materials": recipe.materials,
            "policy": recipe.policy,
            "binaryRetention": if recipe.policy.retain_artifact { "selective" } else { "ephemeral" },
            "latestBuild": latest_build,
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
            "digest": { "sha256": sha256_value(&digest_json(scan)?) },
            "name": "latest-scan-report"
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
                    "source": recipe.source,
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
    use crate::models::{BuilderKind, BuilderRef, Material, Recipe, RecipeInput, SourceRef};

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
}
