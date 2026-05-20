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
                reasons.push(format!("Build security anomaly detected (C2/Malware activity): {}", anomaly));
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
            if finding_denies(finding) {
                reasons.push(format!(
                    "scan finding denies materialization: {} at {}",
                    finding.category, finding.evidence
                ));
            }
        }
        for candidate in &scan.vex_candidates {
            if matches!(
                candidate.status,
                VexStatus::Affected | VexStatus::UnderInvestigation
            ) {
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
    use crate::models::{BuilderKind, BuilderRef, RecipeInput, SourceRef};

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
}
