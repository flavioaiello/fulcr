use std::collections::BTreeSet;

use crate::{
    metadata::slsa_policy_findings,
    models::{
        BuildRecord, FindingSeverity, GateDecision, GateOutcome, Recipe, ScanFinding, ScanReport,
        VexStatement, VexStatus, timestamp,
    },
};

pub fn evaluate_gate(
    recipe: &Recipe,
    latest_build: Option<&BuildRecord>,
    latest_scan: Option<&ScanReport>,
    vex: &[VexStatement],
) -> GateDecision {
    let mut reasons = Vec::new();

    for finding in slsa_policy_findings(recipe, latest_build, latest_scan) {
        if finding_denies(&finding) {
            reasons.push(format!(
                "SLSA posture denies materialization: {} at {}",
                finding.category, finding.evidence
            ));
        }
    }

    for statement in effective_vex_statements(recipe, vex) {
        match statement.status {
            VexStatus::Affected => reasons.push(format!(
                "VEX marks {} as affected for recipe {}",
                statement.vulnerability, recipe.name
            )),
            VexStatus::UnderInvestigation => reasons.push(format!(
                "VEX marks {} as under investigation for recipe {}",
                statement.vulnerability, recipe.name
            )),
            VexStatus::NotAffected | VexStatus::Fixed => {}
        }
    }

    if let Some(scan) = latest_scan {
        for finding in &scan.findings {
            if finding.category == "known-vulnerability"
                && scan
                    .vulnerability_assessments
                    .iter()
                    .any(|candidate| finding_matches_vex_candidate(finding, candidate))
            {
                continue;
            }
            if finding_denies(finding) {
                reasons.push(format!(
                    "scan finding denies materialization: {} at {}",
                    finding.category, finding.evidence
                ));
            }
        }
        for candidate in &scan.vulnerability_assessments {
            if vex_resolves_candidate(recipe, candidate, vex, latest_build) {
                continue;
            }
            match candidate.status {
                VexStatus::Affected => reasons.push(format!(
                    "autonomous VEX marks {} as affected at {}",
                    candidate.vulnerability, candidate.evidence
                )),
                VexStatus::UnderInvestigation => reasons.push(format!(
                    "autonomous VEX is inconclusive for {} at {}",
                    candidate.vulnerability, candidate.evidence
                )),
                VexStatus::NotAffected | VexStatus::Fixed => {
                    if !assessment_is_bound_to_artifact(scan, latest_build) {
                        reasons.push(format!(
                            "autonomous VEX conclusion for {} is not bound to the exact retained artifact",
                            candidate.vulnerability
                        ));
                    }
                }
            }
        }
    }

    GateDecision {
        outcome: if reasons.is_empty() {
            GateOutcome::Allowed
        } else {
            GateOutcome::Denied
        },
        evaluated_at: timestamp(),
        reasons,
    }
}

fn assessment_is_bound_to_artifact(scan: &ScanReport, latest_build: Option<&BuildRecord>) -> bool {
    let Some(artifact_digest) = latest_build
        .and_then(|build| build.artifact.as_ref())
        .map(|artifact| artifact.digest.as_str())
    else {
        return false;
    };
    scan.image.as_ref().is_some_and(|image| {
        image
            .layers
            .iter()
            .any(|layer| layer.digest == artifact_digest)
    })
}

pub fn evaluate_artifact_intake_gate(recipe: &Recipe, source_scan: &ScanReport) -> GateDecision {
    let mut intake_scan = source_scan.clone();
    intake_scan
        .findings
        .retain(|finding| finding.category != "known-vulnerability");
    intake_scan.vulnerability_assessments.clear();
    evaluate_gate(recipe, None, Some(&intake_scan), &[])
}

fn effective_vex_statements<'a>(recipe: &Recipe, vex: &'a [VexStatement]) -> Vec<&'a VexStatement> {
    let mut seen = BTreeSet::new();
    let mut effective = Vec::new();
    for statement in vex.iter().rev() {
        if statement.recipe_digest != recipe.digest {
            continue;
        }
        let key = (
            statement.vulnerability.clone(),
            statement.product.clone(),
            statement.component.clone(),
        );
        if seen.insert(key) {
            effective.push(statement);
        }
    }
    effective
}

fn finding_matches_vex_candidate(
    finding: &ScanFinding,
    candidate: &crate::models::VulnerabilityAssessment,
) -> bool {
    finding.message.contains(&candidate.vulnerability) && finding.evidence == candidate.evidence
}

fn vex_resolves_candidate(
    recipe: &Recipe,
    candidate: &crate::models::VulnerabilityAssessment,
    vex: &[VexStatement],
    latest_build: Option<&BuildRecord>,
) -> bool {
    if !recipe.policy.allow_external_vex_overrides
        || !matches!(candidate.status, VexStatus::UnderInvestigation)
    {
        return false;
    }
    let Some(expected_product) = latest_build
        .and_then(|build| build.artifact.as_ref())
        .map(|artifact| format!("urn:oci:blob:{}", artifact.digest))
    else {
        return false;
    };
    vex.iter()
        .rev()
        .find(|statement| {
            statement.recipe_digest == recipe.digest
                && statement.vulnerability == candidate.vulnerability
                && statement.component.as_deref() == Some(candidate.component.as_str())
                && statement.product.as_deref() == Some(expected_product.as_str())
                && statement
                    .author
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
        })
        .is_some_and(|statement| {
            statement.status == VexStatus::NotAffected && vex_statement_is_unexpired(statement)
        })
}

fn vex_statement_is_unexpired(statement: &VexStatement) -> bool {
    statement.expires_at.as_deref().is_some_and(|expires_at| {
        time::OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339)
            .is_ok_and(|expires_at| expires_at > time::OffsetDateTime::now_utc())
    })
}

fn finding_denies(finding: &ScanFinding) -> bool {
    matches!(
        finding.severity,
        FindingSeverity::High | FindingSeverity::Critical
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        ArtifactRef, BuildStatus, BuilderKind, BuilderRef, ImageLayerMetadata, ImageScanMetadata,
        RecipeInput, ScanMode, ScanStatus, ScanSummary, SourceRef, VulnerabilityAssessment,
    };

    #[test]
    fn denies_affected_vex() {
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
                digest: Some("sha256:builder".to_string()),
            },
            build: Default::default(),
            materials: Vec::new(),
            crypto: Vec::new(),
            policy: Default::default(),
            annotations: Default::default(),
        })
        .unwrap();

        let decision = evaluate_gate(
            &recipe,
            None,
            None,
            &[VexStatement {
                id: uuid::Uuid::new_v4(),
                recipe_id: recipe.id,
                recipe_digest: recipe.digest.clone(),
                created_at: timestamp(),
                vulnerability: "CVE-2026-0001".to_string(),
                status: VexStatus::Affected,
                product: None,
                component: None,
                justification: None,
                detail: None,
                author: None,
                expires_at: None,
            }],
        );

        assert_eq!(decision.outcome, GateOutcome::Denied);
    }

    #[test]
    fn denies_weak_slsa_posture() {
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "main".to_string(),
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

        let decision = evaluate_gate(&recipe, None, None, &[]);

        assert_eq!(decision.outcome, GateOutcome::Denied);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("SLSA posture denies materialization"))
        );
    }

    #[test]
    fn not_affected_vex_resolves_matching_scan_candidate() {
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
                name: Some("local".to_string()),
                digest: Some(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                ),
            },
            build: Default::default(),
            materials: Vec::new(),
            crypto: Vec::new(),
            policy,
            annotations: Default::default(),
        })
        .unwrap();

        let layer_digest = format!("sha256:{}", "c".repeat(64));
        let build = retained_build(&recipe, &layer_digest);
        let scan = ScanReport {
            id: uuid::Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            created_at: timestamp(),
            scanner: "test".to_string(),
            filesystem_digest: None,
            declared_artifact_digest: None,
            mode: ScanMode::Filesystem,
            root: std::path::PathBuf::from("."),
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
            findings: vec![ScanFinding {
                severity: FindingSeverity::High,
                category: "known-vulnerability".to_string(),
                message: "component openssl has a known vulnerability: CVE-2026-0001".to_string(),
                evidence: "Cargo.lock#openssl".to_string(),
            }],
            vulnerability_assessments: vec![VulnerabilityAssessment {
                vulnerability: "CVE-2026-0001".to_string(),
                status: VexStatus::UnderInvestigation,
                component: "openssl".to_string(),
                justification: "requires_triage".to_string(),
                detail: "detected by OSV".to_string(),
                evidence: "Cargo.lock#openssl".to_string(),
            }],
            sbom: serde_json::json!({}),
            cbom: serde_json::json!({}),
        };

        let decision = evaluate_gate(
            &recipe,
            Some(&build),
            Some(&scan),
            &[
                VexStatement {
                    id: uuid::Uuid::new_v4(),
                    recipe_id: recipe.id,
                    recipe_digest: recipe.digest.clone(),
                    created_at: timestamp(),
                    vulnerability: "CVE-2026-0001".to_string(),
                    status: VexStatus::Affected,
                    product: Some(format!("urn:oci:blob:{layer_digest}")),
                    component: Some("openssl".to_string()),
                    justification: None,
                    detail: None,
                    author: None,
                    expires_at: None,
                },
                VexStatement {
                    id: uuid::Uuid::new_v4(),
                    recipe_id: recipe.id,
                    recipe_digest: recipe.digest.clone(),
                    created_at: timestamp(),
                    vulnerability: "CVE-2026-0001".to_string(),
                    status: VexStatus::NotAffected,
                    product: Some(format!("urn:oci:blob:{layer_digest}")),
                    component: Some("openssl".to_string()),
                    justification: Some("vulnerable_code_not_present".to_string()),
                    detail: Some("external artifact-bound analysis".to_string()),
                    author: Some("security@example.invalid".to_string()),
                    expires_at: Some("2999-01-01T00:00:00Z".to_string()),
                },
            ],
        );

        assert_eq!(decision.outcome, GateOutcome::Allowed);
    }

    #[test]
    fn componentless_vex_does_not_resolve_scan_candidate() {
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: None,
            },
            builder: BuilderRef {
                kind: BuilderKind::Script,
                name: Some("local".to_string()),
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

        let scan = ScanReport {
            id: uuid::Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            created_at: timestamp(),
            scanner: "test".to_string(),
            filesystem_digest: None,
            declared_artifact_digest: None,
            mode: ScanMode::Source,
            root: std::path::PathBuf::from("."),
            image: None,
            status: ScanStatus::CompletedWithFindings,
            summary: ScanSummary::default(),
            components: Vec::new(),
            crypto: Vec::new(),
            binaries: Vec::new(),
            findings: vec![ScanFinding {
                severity: FindingSeverity::High,
                category: "known-vulnerability".to_string(),
                message: "component openssl has a known vulnerability: CVE-2026-0001".to_string(),
                evidence: "Cargo.lock#openssl".to_string(),
            }],
            vulnerability_assessments: vec![VulnerabilityAssessment {
                vulnerability: "CVE-2026-0001".to_string(),
                status: VexStatus::UnderInvestigation,
                component: "openssl".to_string(),
                justification: "requires_triage".to_string(),
                detail: "detected by OSV".to_string(),
                evidence: "Cargo.lock#openssl".to_string(),
            }],
            sbom: serde_json::json!({}),
            cbom: serde_json::json!({}),
        };

        let decision = evaluate_gate(
            &recipe,
            None,
            Some(&scan),
            &[VexStatement {
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
            }],
        );

        assert_eq!(decision.outcome, GateOutcome::Denied);
    }

    #[test]
    fn source_assessment_cannot_resolve_without_artifact_binding() {
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: None,
            },
            builder: BuilderRef {
                kind: BuilderKind::Script,
                name: Some("local".to_string()),
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

        let scan = ScanReport {
            id: uuid::Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            created_at: timestamp(),
            scanner: "test".to_string(),
            filesystem_digest: None,
            declared_artifact_digest: None,
            mode: ScanMode::Source,
            root: std::path::PathBuf::from("."),
            image: None,
            status: ScanStatus::CompletedWithFindings,
            summary: ScanSummary::default(),
            components: Vec::new(),
            crypto: Vec::new(),
            binaries: Vec::new(),
            findings: vec![ScanFinding {
                severity: FindingSeverity::High,
                category: "known-vulnerability".to_string(),
                message: "component openssl has a known vulnerability: CVE-2026-0001".to_string(),
                evidence: "Cargo.lock#openssl".to_string(),
            }],
            vulnerability_assessments: vec![VulnerabilityAssessment {
                vulnerability: "CVE-2026-0001".to_string(),
                status: VexStatus::NotAffected,
                component: "openssl".to_string(),
                justification: "scanner_claim".to_string(),
                detail: "candidate status alone is not durable VEX evidence".to_string(),
                evidence: "Cargo.lock#openssl".to_string(),
            }],
            sbom: serde_json::json!({}),
            cbom: serde_json::json!({}),
        };

        let decision = evaluate_gate(&recipe, None, Some(&scan), &[]);

        assert_eq!(decision.outcome, GateOutcome::Denied);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("not bound to the exact retained artifact"))
        );
    }

    #[test]
    fn external_vex_is_disabled_by_default() {
        let recipe = tight_recipe(Default::default());
        let scan = vulnerability_scan(&recipe, VexStatus::UnderInvestigation);
        let external = resolving_statement(&recipe);

        let decision = evaluate_gate(&recipe, None, Some(&scan), &[external]);

        assert_eq!(decision.outcome, GateOutcome::Denied);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("autonomous VEX is inconclusive"))
        );
    }

    #[test]
    fn expired_external_vex_does_not_resolve_inconclusive_assessment() {
        let policy = crate::models::RetentionPolicy {
            allow_external_vex_overrides: true,
            ..Default::default()
        };
        let recipe = tight_recipe(policy);
        let layer_digest = format!("sha256:{}", "d".repeat(64));
        let build = retained_build(&recipe, &layer_digest);
        let mut scan = vulnerability_scan(&recipe, VexStatus::UnderInvestigation);
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
        let mut external = resolving_statement(&recipe);
        external.product = Some(format!("urn:oci:blob:{layer_digest}"));
        external.expires_at = Some("2000-01-01T00:00:00Z".to_string());

        let decision = evaluate_gate(&recipe, Some(&build), Some(&scan), &[external]);

        assert_eq!(decision.outcome, GateOutcome::Denied);
        assert!(
            decision
                .reasons
                .iter()
                .any(|reason| reason.contains("autonomous VEX is inconclusive"))
        );
    }

    #[test]
    fn external_vex_cannot_override_autonomous_affected() {
        let policy = crate::models::RetentionPolicy {
            allow_external_vex_overrides: true,
            ..Default::default()
        };
        let recipe = tight_recipe(policy);
        let scan = vulnerability_scan(&recipe, VexStatus::Affected);
        let external = resolving_statement(&recipe);

        let decision = evaluate_gate(&recipe, None, Some(&scan), &[external]);

        assert_eq!(decision.outcome, GateOutcome::Denied);
        assert!(
            decision.reasons.iter().any(
                |reason| reason.contains("autonomous VEX marks") && reason.contains("affected")
            )
        );
    }

    #[test]
    fn artifact_bound_autonomous_fixed_allows_without_external_vex() {
        let recipe = tight_recipe(Default::default());
        let layer_digest = format!("sha256:{}", "a".repeat(64));
        let mut scan = vulnerability_scan(&recipe, VexStatus::Fixed);
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
        let build = BuildRecord {
            id: uuid::Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            source_scan_id: Some(uuid::Uuid::new_v4()),
            source_scan_digest: Some(format!("sha256:{}", "b".repeat(64))),
            artifact_scan_id: Some(scan.id),
            policy_decision: None,
            status: BuildStatus::Succeeded,
            created_at: timestamp(),
            started_at: Some(timestamp()),
            finished_at: Some(timestamp()),
            command: Vec::new(),
            working_dir: None,
            exit_code: None,
            artifact: Some(ArtifactRef {
                digest: layer_digest.clone(),
                diff_id: Some(layer_digest),
                media_type: Some("application/vnd.oci.image.layer.v1.tar".to_string()),
                size: 1024,
                retained: true,
                path: None,
                expires_at: None,
            }),
            stdout_tail: None,
            stderr_tail: None,
            notes: Vec::new(),
        };

        let decision = evaluate_gate(&recipe, Some(&build), Some(&scan), &[]);

        assert_eq!(decision.outcome, GateOutcome::Allowed);
    }

    #[test]
    fn artifact_intake_ignores_only_vulnerability_matches() {
        let recipe = tight_recipe(Default::default());
        let source_scan = vulnerability_scan(&recipe, VexStatus::UnderInvestigation);
        assert_eq!(
            evaluate_artifact_intake_gate(&recipe, &source_scan).outcome,
            GateOutcome::Allowed
        );

        let mut unsafe_scan = source_scan;
        unsafe_scan.findings.push(ScanFinding {
            severity: FindingSeverity::High,
            category: "private-key-material".to_string(),
            message: "private key present".to_string(),
            evidence: "secret.key".to_string(),
        });
        assert_eq!(
            evaluate_artifact_intake_gate(&recipe, &unsafe_scan).outcome,
            GateOutcome::Denied
        );
    }

    fn tight_recipe(policy: crate::models::RetentionPolicy) -> Recipe {
        Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: None,
            },
            builder: BuilderRef {
                kind: BuilderKind::Script,
                name: Some("local".to_string()),
                digest: Some(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                ),
            },
            build: Default::default(),
            materials: Vec::new(),
            crypto: Vec::new(),
            policy,
            annotations: Default::default(),
        })
        .unwrap()
    }

    fn vulnerability_scan(recipe: &Recipe, status: VexStatus) -> ScanReport {
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
            status: ScanStatus::CompletedWithFindings,
            summary: ScanSummary::default(),
            components: Vec::new(),
            crypto: Vec::new(),
            binaries: Vec::new(),
            findings: vec![ScanFinding {
                severity: FindingSeverity::High,
                category: "known-vulnerability".to_string(),
                message: "component openssl has a known vulnerability: CVE-2026-0001".to_string(),
                evidence: "rootfs/Cargo.lock#openssl".to_string(),
            }],
            vulnerability_assessments: vec![VulnerabilityAssessment {
                vulnerability: "CVE-2026-0001".to_string(),
                status,
                component: "openssl".to_string(),
                justification: "autonomous_test".to_string(),
                detail: "machine assessment".to_string(),
                evidence: "rootfs/Cargo.lock#openssl".to_string(),
            }],
            sbom: serde_json::json!({}),
            cbom: serde_json::json!({}),
        }
    }

    fn resolving_statement(recipe: &Recipe) -> VexStatement {
        VexStatement {
            id: uuid::Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            created_at: timestamp(),
            vulnerability: "CVE-2026-0001".to_string(),
            status: VexStatus::NotAffected,
            product: None,
            component: Some("openssl".to_string()),
            justification: Some("external_exception".to_string()),
            detail: Some("approved exception".to_string()),
            author: Some("security@example.invalid".to_string()),
            expires_at: Some("2999-01-01T00:00:00Z".to_string()),
        }
    }

    fn retained_build(recipe: &Recipe, layer_digest: &str) -> BuildRecord {
        BuildRecord {
            id: uuid::Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            source_scan_id: Some(uuid::Uuid::new_v4()),
            source_scan_digest: Some(format!("sha256:{}", "b".repeat(64))),
            artifact_scan_id: None,
            policy_decision: None,
            status: BuildStatus::Succeeded,
            created_at: timestamp(),
            started_at: Some(timestamp()),
            finished_at: Some(timestamp()),
            command: Vec::new(),
            working_dir: None,
            exit_code: None,
            artifact: Some(ArtifactRef {
                digest: layer_digest.to_string(),
                diff_id: Some(layer_digest.to_string()),
                media_type: Some("application/vnd.oci.image.layer.v1.tar".to_string()),
                size: 1024,
                retained: true,
                path: None,
                expires_at: None,
            }),
            stdout_tail: None,
            stderr_tail: None,
            notes: Vec::new(),
        }
    }

    #[test]
    fn medium_unstructured_finding_does_not_deny() {
        let finding = ScanFinding {
            severity: FindingSeverity::Medium,
            category: "crypto-policy-drift".to_string(),
            message: "unstructured text mentions MD5".to_string(),
            evidence: "notes.txt".to_string(),
        };

        assert!(!finding_denies(&finding));
    }
}
