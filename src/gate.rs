use crate::{
    metadata::slsa_policy_findings,
    models::{
        timestamp, BuildRecord, FindingSeverity, GateDecision, GateOutcome, Recipe, ScanFinding,
        ScanReport, VexStatement, VexStatus,
    },
};

pub fn evaluate_gate(
    recipe: &Recipe,
    latest_build: Option<&BuildRecord>,
    latest_scan: Option<&ScanReport>,
    vex: &[VexStatement],
) -> GateDecision {
    let mut reasons = Vec::new();

    if let Some(build) = latest_build {
        if !build.security_anomalies.is_empty() {
            for anomaly in &build.security_anomalies {
                reasons.push(format!(
                    "Build security anomaly detected (C2/Malware activity): {}",
                    anomaly
                ));
            }
        }
    }

    for finding in slsa_policy_findings(recipe, latest_build, latest_scan) {
        if finding_denies(&finding) {
            reasons.push(format!(
                "SLSA posture denies materialization: {} at {}",
                finding.category, finding.evidence
            ));
        }
    }

    for statement in vex {
        // Ignore overrides that were bound to a different recipe digest. The intake API
        // enforces this on write, but defense-in-depth on read protects against legacy
        // statements created before digest binding existed.
        if statement.recipe_digest != recipe.digest {
            continue;
        }
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
                && scan.vex_candidates.iter().any(|candidate| {
                    finding_matches_vex_candidate(finding, candidate)
                        && (vex_candidate_requires_triage(candidate)
                            || vex_resolves_candidate(recipe, candidate, vex))
                })
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
        for candidate in &scan.vex_candidates {
            if vex_resolves_candidate(recipe, candidate, vex) {
                continue;
            }
            if vex_candidate_requires_triage(candidate) {
                reasons.push(format!(
                    "VEX candidate requires triage: {} at {}",
                    candidate.vulnerability, candidate.evidence
                ));
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

fn finding_matches_vex_candidate(
    finding: &ScanFinding,
    candidate: &crate::models::VexCandidate,
) -> bool {
    finding.message.contains(&candidate.vulnerability) && finding.evidence == candidate.evidence
}

fn vex_candidate_requires_triage(candidate: &crate::models::VexCandidate) -> bool {
    matches!(
        candidate.status,
        VexStatus::Affected | VexStatus::UnderInvestigation
    )
}

fn vex_resolves_candidate(
    recipe: &Recipe,
    candidate: &crate::models::VexCandidate,
    vex: &[VexStatement],
) -> bool {
    vex.iter().any(|statement| {
        if statement.recipe_digest != recipe.digest
            || statement.vulnerability != candidate.vulnerability
        {
            return false;
        }
        let Some(component) = statement.component.as_deref() else {
            return false;
        };
        if component != candidate.component {
            return false;
        }
        matches!(statement.status, VexStatus::NotAffected | VexStatus::Fixed)
    })
}

fn finding_denies(finding: &ScanFinding) -> bool {
    matches!(
        finding.severity,
        FindingSeverity::High | FindingSeverity::Critical
    ) || matches!(
        finding.category.as_str(),
        "ad-hoc-binary"
            | "suspicious-build-behavior"
            | "sbom-lifecycle-script"
            | "sbom-missing-integrity"
            | "sbom-suspicious-package-script"
            | "sbom-unpinned-dependency"
            | "sbom-untrusted-source"
            | "slsa-artifact-not-fingerprinted"
            | "slsa-build-failed"
            | "slsa-durable-metadata-disabled"
            | "slsa-incomplete-build-timestamps"
            | "slsa-missing-scan-evidence"
            | "slsa-stale-build-evidence"
            | "slsa-stale-scan-evidence"
            | "slsa-undigested-material"
            | "slsa-unpinned-builder"
            | "slsa-unpinned-source"
            | "binary-crypto-policy-drift"
            | "crypto-policy-drift"
            | "metadata-misalignment"
            | "private-key-material"
            | "osv-lookup-failed"
            | "known-vulnerability"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        BuilderKind, BuilderRef, RecipeInput, ScanMode, ScanStatus, ScanSummary, SourceRef,
        VexCandidate,
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
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason.contains("SLSA posture denies materialization")));
    }

    #[test]
    fn not_affected_vex_resolves_matching_scan_candidate() {
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
            vex_candidates: vec![VexCandidate {
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
                component: Some("openssl".to_string()),
                justification: None,
                detail: None,
                author: None,
            }],
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
            vex_candidates: vec![VexCandidate {
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
            }],
        );

        assert_eq!(decision.outcome, GateOutcome::Denied);
    }

    #[test]
    fn scan_candidate_does_not_resolve_itself_without_vex() {
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
            vex_candidates: vec![VexCandidate {
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
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason.contains("scan finding denies materialization")));
    }
}
