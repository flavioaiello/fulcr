use std::{collections::BTreeMap, fs, path::Path, path::PathBuf};

use anyhow::Context;
use ignore::{DirEntry, WalkBuilder};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    binary, image,
    models::{
        timestamp, BinaryAnalysis, FindingSeverity, ImageScanMetadata, Recipe, ScanFinding,
        ScanMode, ScanReport, ScanRequest, ScanStatus, ScanSummary, ScannedComponent,
        ScannedCryptoMaterial, VexCandidate, VexStatus,
    },
};

const SCANNER_NAME: &str = "fulcr-native-scanner/0.1";
const DEFAULT_MAX_FILE_BYTES: u64 = 1024 * 1024;

pub async fn scan_recipe(
    recipe: &Recipe,
    request: ScanRequest,
    work_dir: &Path,
) -> anyhow::Result<ScanReport> {
    let recipe_clone = recipe.clone();
    let work_dir_clone = work_dir.to_path_buf();
    let mut report = tokio::task::spawn_blocking(move || {
        scan_recipe_blocking(&recipe_clone, request, &work_dir_clone)
    })
    .await
    .context("scanner worker failed")??;

    enrich_report_with_osv(recipe, &mut report).await;

    Ok(report)
}

async fn enrich_report_with_osv(recipe: &Recipe, report: &mut ScanReport) {
    let mut queries = Vec::new();
    let mut mapped_components = Vec::new();

    for component in &report.components {
        let ecosystem = match component.kind.as_str() {
            "cargo" | "cargo-declared" => "crates.io",
            "npm" | "npm-declared" => "npm",
            "pypi" => "PyPI",
            "go" => "Go",
            "maven" => "Maven",
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
        return;
    }

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let mut osv_failed = false;

    for (query_chunk, component_chunk) in queries.chunks(1000).zip(mapped_components.chunks(1000)) {
        let request = serde_json::json!({ "queries": query_chunk });

        let response = match client
            .post("https://api.osv.dev/v1/querybatch")
            .json(&request)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                tracing::warn!("OSV logic failed: {}", err);
                osv_failed = true;
                continue;
            }
        };

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

        for (i, result) in results.iter().enumerate() {
            let Some(vulns) = result.get("vulns").and_then(|v| v.as_array()) else {
                continue;
            };

            for vuln in vulns {
                let Some(id) = vuln.get("id").and_then(|id| id.as_str()) else {
                    continue;
                };
                let component = &component_chunk[i];
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

                report.vex_candidates.push(VexCandidate {
                    vulnerability: vulnerability.clone(),
                    status: VexStatus::UnderInvestigation,
                    component: component.name.clone(),
                    justification: "requires_triage".to_string(),
                    detail: format!(
                        "Vulnerability {} detected in {} via OSV database.",
                        vulnerability, component.name
                    ),
                    evidence: component.evidence.clone(),
                });
            }
        }
    }

    if osv_failed {
        report.findings.push(ScanFinding {
            severity: FindingSeverity::High,
            category: "osv-lookup-failed".to_string(),
            message: "Failed to validate components against OSV database".to_string(),
            evidence: "api.osv.dev".to_string(),
        });
    }

    report.status = if report.findings.is_empty() {
        ScanStatus::Completed
    } else {
        ScanStatus::CompletedWithFindings
    };
    report.summary.findings_detected = report.findings.len();
    report.summary.vex_candidates_detected = report.vex_candidates.len();
    report.sbom = build_sbom(
        recipe,
        &report.components,
        &report.findings,
        &report.created_at,
    );
    report.cbom = build_cbom(recipe, &report.crypto, &report.findings, &report.created_at);
}

fn scan_recipe_blocking(
    recipe: &Recipe,
    request: ScanRequest,
    work_dir: &Path,
) -> anyhow::Result<ScanReport> {
    let max_file_bytes = request.max_file_bytes.unwrap_or(DEFAULT_MAX_FILE_BYTES);

    match request.mode {
        ScanMode::ImageArchive => {
            let archive = request
                .path
                .as_ref()
                .context("image archive scan requires request.path")?;
            let archive_canon = fs::canonicalize(archive)
                .with_context(|| format!("canonicalizing {}", archive.display()))?;
            if !archive_canon.starts_with(work_dir) {
                anyhow::bail!("image archive path escapes the configured work dir");
            }
            let unpacked = image::unpack_image_archive(&archive_canon)?;
            scan_filesystem_report(
                recipe,
                &unpacked.rootfs,
                unpacked.metadata.archive.clone(),
                ScanMode::ImageArchive,
                Some(unpacked.metadata),
                max_file_bytes,
            )
        }
        ScanMode::Source | ScanMode::Filesystem => {
            let root = request
                .path
                .clone()
                .or_else(|| recipe.source.path.clone())
                .unwrap_or_else(|| PathBuf::from("."));
            let root = fs::canonicalize(&root)
                .with_context(|| format!("canonicalizing {}", root.display()))?;
            if !root.starts_with(work_dir) {
                anyhow::bail!("scan root escapes the configured work dir");
            }
            scan_filesystem_report(
                recipe,
                &root,
                root.clone(),
                request.mode,
                None,
                max_file_bytes,
            )
        }
    }
}

fn scan_filesystem_report(
    recipe: &Recipe,
    root: &Path,
    report_root: PathBuf,
    mode: ScanMode,
    image: Option<ImageScanMetadata>,
    max_file_bytes: u64,
) -> anyhow::Result<ScanReport> {
    let mut scanner = ScannerState::default();

    let walker = WalkBuilder::new(root)
        .follow_links(false)
        .hidden(false)
        .parents(true)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .filter_entry(should_descend)
        .build();

    for entry in walker {
        let entry = entry.with_context(|| format!("walking {}", root.display()))?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }

        scanner.files_scanned += 1;
        scan_file(recipe, root, entry.path(), max_file_bytes, &mut scanner)?;
    }

    compare_recipe_metadata(recipe, &mut scanner);

    let created_at = timestamp();
    let components = scanner.components.into_values().collect::<Vec<_>>();
    let crypto = scanner.crypto.into_values().collect::<Vec<_>>();
    let binaries = scanner.binaries.into_values().collect::<Vec<_>>();
    let findings = scanner.findings;
    let vex_candidates = scanner.vex_candidates.into_values().collect::<Vec<_>>();
    let sbom = build_sbom(recipe, &components, &findings, &created_at);
    let cbom = build_cbom(recipe, &crypto, &findings, &created_at);
    let status = if findings.is_empty() {
        ScanStatus::Completed
    } else {
        ScanStatus::CompletedWithFindings
    };
    let summary = ScanSummary {
        files_scanned: scanner.files_scanned,
        components_detected: components.len(),
        crypto_materials_detected: crypto.len(),
        binaries_analyzed: binaries.len(),
        findings_detected: findings.len(),
        vex_candidates_detected: vex_candidates.len(),
    };

    Ok(ScanReport {
        id: Uuid::new_v4(),
        recipe_id: recipe.id,
        recipe_digest: recipe.digest.clone(),
        created_at,
        scanner: SCANNER_NAME.to_string(),
        mode,
        root: report_root,
        image,
        status,
        summary,
        components,
        crypto,
        binaries,
        findings,
        vex_candidates,
        sbom,
        cbom,
    })
}

fn should_descend(entry: &DirEntry) -> bool {
    if !entry
        .file_type()
        .is_some_and(|file_type| file_type.is_dir())
    {
        return true;
    }

    !matches!(
        entry.file_name().to_string_lossy().as_ref(),
        ".git" | ".fulcr" | "node_modules" | "target" | ".terraform" | "dist" | "build"
    )
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
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let path_text = evidence.replace('\\', "/");
    let executable = is_executable(&metadata);

    if metadata.len() > max_file_bytes {
        if is_known_metadata_file(&path_text, file_name) {
            scanner.findings.push(ScanFinding {
                severity: FindingSeverity::Low,
                category: "metadata-file-too-large".to_string(),
                message: "metadata file exceeded scanner size limit".to_string(),
                evidence: evidence.clone(),
            });
        }
        return Ok(());
    }

    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let digest = Some(crate::digest::digest_bytes(&bytes));
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
        "pom.xml" => parse_pom_xml(&text, &evidence, digest, scanner),
        "packages.lock.json" => {
            add_manifest_component("nuget-lock", None, "nuget", &evidence, digest, scanner)
        }
        _ => {}
    }

    if path_text.ends_with("var/lib/dpkg/status") {
        parse_dpkg_status(&text, &evidence, scanner);
    }
    if path_text.ends_with("lib/apk/db/installed") {
        parse_apk_installed(&text, &evidence, scanner);
    }

    scan_crypto_material(path, &path_text, &text, scanner);
    if !is_documentation_file(&path_text, file_name) {
        scan_suspicious_text(&path_text, &text, scanner);
    }
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
        for candidate in output.vex_candidates {
            scanner.add_vex_candidate(candidate);
        }
    }

    if !executable {
        return;
    }
    let digest = crate::digest::digest_bytes(bytes);
    scanner.findings.push(ScanFinding {
        severity: FindingSeverity::Medium,
        category: "ad-hoc-binary".to_string(),
        message: "executable binary exists in scanned source or image content".to_string(),
        evidence: format!("{evidence} ({digest})"),
    });
    scanner.add_vex_candidate(VexCandidate {
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
                    FindingSeverity::Medium,
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
            severity: FindingSeverity::Low,
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
            severity: FindingSeverity::Low,
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
                    format!("npm script {name} references credential, token, registry, or publish behavior"),
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
            severity: FindingSeverity::Low,
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
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }

        let (name, version) = split_requirement(line);
        if !name.is_empty() {
            enforce_python_requirement_policy(name, version.as_deref(), line, evidence, scanner);
            add_component(name.to_string(), version, "pypi", evidence, None, scanner);
        }
    }
}

fn parse_go_mod(text: &str, evidence: &str, scanner: &mut ScannerState) {
    let mut in_require_block = false;
    for line in text.lines() {
        let line = line.trim();
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
            add_component(name.to_string(), version, "go", evidence, None, scanner);
        }
    }
}

fn parse_pom_xml(text: &str, evidence: &str, digest: Option<String>, scanner: &mut ScannerState) {
    let Ok(document) = roxmltree::Document::parse(text) else {
        scanner.findings.push(ScanFinding {
            severity: FindingSeverity::Low,
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
        if version
            .as_deref()
            .is_some_and(|version| version.contains("${"))
        {
            add_sbom_policy_finding(
                scanner,
                FindingSeverity::Medium,
                ("sbom-unpinned-dependency", "fulcr-SBOM-UNPINNED-DEPENDENCY"),
                &name,
                format!("Maven dependency {name} uses a property-substituted version"),
                evidence.to_string(),
                "dependency_version_requires_triage",
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
        if documentation {
            break;
        }
        if lower.contains(needle) {
            scanner.add_crypto(ScannedCryptoMaterial {
                name: algorithm.to_string(),
                kind: "algorithm-or-protocol".to_string(),
                algorithm: Some(algorithm.to_string()),
                purpose: Some("observed-in-source-or-config".to_string()),
                evidence: evidence.to_string(),
            });
            scanner.findings.push(ScanFinding {
                severity,
                category: "crypto-policy-drift".to_string(),
                message: format!("legacy or sensitive crypto primitive observed: {algorithm}"),
                evidence: evidence.to_string(),
            });
            scanner.add_vex_candidate(VexCandidate {
                vulnerability: "fulcr-CRYPTO-POLICY-DRIFT".to_string(),
                status: VexStatus::UnderInvestigation,
                component: algorithm.to_string(),
                justification: "crypto_policy_requires_triage".to_string(),
                detail: format!("{algorithm} was observed during metadata scanning."),
                evidence: evidence.to_string(),
            });
        }
    }

    for (needle, library) in [
        ("openssl", "OpenSSL"),
        ("rustls", "rustls"),
        ("ring::", "ring"),
    ] {
        if documentation {
            break;
        }
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
        if documentation {
            break;
        }
        if lower.contains(needle) {
            scanner.add_crypto(ScannedCryptoMaterial {
                name: material.to_string(),
                kind: "disallowed-crypto-policy-material".to_string(),
                algorithm: Some(material.to_string()),
                purpose: Some("observed-in-source-config-or-binary".to_string()),
                evidence: evidence.to_string(),
            });
            scanner.findings.push(ScanFinding {
                severity,
                category: "crypto-policy-drift".to_string(),
                message: format!("disallowed or expired crypto material observed: {material}"),
                evidence: evidence.to_string(),
            });
            scanner.add_vex_candidate(VexCandidate {
                vulnerability: "fulcr-CRYPTO-POLICY-DRIFT".to_string(),
                status: VexStatus::UnderInvestigation,
                component: material.to_string(),
                justification: "crypto_policy_requires_triage".to_string(),
                detail: format!("{material} violates the default CBOM crypto posture."),
                evidence: evidence.to_string(),
            });
        }
    }
}

fn scan_suspicious_text(evidence: &str, text: &str, scanner: &mut ScannerState) {
    let lower = text.to_ascii_lowercase();
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

    if suspicious
        .iter()
        .any(|(left, right)| lower.contains(left) && (right.is_empty() || lower.contains(right)))
    {
        scanner.findings.push(ScanFinding {
            severity: FindingSeverity::High,
            category: "suspicious-build-behavior".to_string(),
            message: "script contains remote execution, reverse shell, or encoded command pattern"
                .to_string(),
            evidence: evidence.to_string(),
        });
        scanner.add_vex_candidate(VexCandidate {
            vulnerability: "fulcr-SUSPICIOUS-BUILD-BEHAVIOR".to_string(),
            status: VexStatus::UnderInvestigation,
            component: evidence.to_string(),
            justification: "unexpected_network_or_command_execution_requires_triage".to_string(),
            detail: "Potential command-and-control or remote-code execution pattern was observed."
                .to_string(),
            evidence: evidence.to_string(),
        });
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

fn compare_recipe_metadata(recipe: &Recipe, scanner: &mut ScannerState) {
    for material in &recipe.materials {
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
                FindingSeverity::Medium,
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
    if !is_exact_version_spec(spec) {
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
            FindingSeverity::Medium,
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
            FindingSeverity::Medium,
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
        scanner.add_vex_candidate(VexCandidate {
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

fn is_exact_version_spec(spec: &str) -> bool {
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
            | "pom.xml"
    ) || path.ends_with("var/lib/dpkg/status")
        || path.ends_with("lib/apk/db/installed")
}

fn looks_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(1024).any(|byte| *byte == 0)
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
    components: BTreeMap<String, ScannedComponent>,
    crypto: BTreeMap<String, ScannedCryptoMaterial>,
    binaries: BTreeMap<String, BinaryAnalysis>,
    findings: Vec<ScanFinding>,
    vex_candidates: BTreeMap<String, VexCandidate>,
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

    fn add_vex_candidate(&mut self, candidate: VexCandidate) {
        let key = format!(
            "{}|{}|{}",
            candidate.vulnerability, candidate.component, candidate.evidence
        );
        self.vex_candidates.entry(key).or_insert(candidate);
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use crate::models::{BuilderKind, BuilderRef, RecipeInput, SourceRef};

    use super::*;

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
            ScanRequest::default(),
            fs::canonicalize(temp.path()).unwrap().as_path(),
        )
        .await
        .unwrap();

        assert!(report
            .components
            .iter()
            .any(|component| component.name == "serde"));
        assert!(report
            .crypto
            .iter()
            .any(|item| item.algorithm.as_deref() == Some("TLS 1.0")));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.category == "suspicious-build-behavior"));
        assert!(report
            .vex_candidates
            .iter()
            .any(|candidate| candidate.vulnerability == "fulcr-ADHOC-BINARY"));
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

        fs::write(image_dir.join("config.json"), "{}").unwrap();
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
            },
            fs::canonicalize(temp.path()).unwrap().as_path(),
        )
        .await
        .unwrap();

        assert!(matches!(report.mode, ScanMode::ImageArchive));
        assert_eq!(report.image.unwrap().kind, "docker-archive");
        assert!(report
            .components
            .iter()
            .any(|component| component.name == "bash" && component.kind == "deb"));
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
            ScanRequest::default(),
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
        assert!(report.sbom["fulcrPolicyFindings"]
            .as_array()
            .is_some_and(|findings| !findings.is_empty()));
        assert!(report.cbom["findings"]
            .as_array()
            .is_some_and(|findings| !findings.is_empty()));
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
            ScanRequest::default(),
            fs::canonicalize(temp.path()).unwrap().as_path(),
        )
        .await
        .unwrap();

        assert!(report
            .components
            .iter()
            .any(|component| { component.kind == "cargo-declared" && component.name == "serde" }));
        assert!(report
            .components
            .iter()
            .any(|component| component.kind == "npm" && component.name == "left-pad"));
        assert!(report.components.iter().any(|component| {
            component.kind == "maven" && component.name == "org.slf4j:slf4j-api"
        }));
        assert!(report
            .crypto
            .iter()
            .any(|item| item.kind == "parsed-private-key"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.category == "sbom-untrusted-source"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.category == "sbom-missing-integrity"));
    }
}
