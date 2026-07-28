use std::{collections::BTreeSet, fs};

use fulcr::{
    gate,
    models::{
        BuilderKind, BuilderRef, GateOutcome, OsvMode, Recipe, RecipeInput, ScanRequest, SourceRef,
    },
    scanner,
};

const IMMUTABLE_REVISION: &str = "0123456789abcdef0123456789abcdef01234567";
const BUILDER_DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[tokio::test]
async fn contains_visible_npm_worm_install_script_from_lockfile() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        fs::canonicalize(temp.path())
            .unwrap()
            .as_path()
            .join("package.json"),
        r#"{
  "name": "victim-app",
  "version": "1.0.0",
  "dependencies": {
    "sha1-hulud-payload": "1.2.3"
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
  "name": "victim-app",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "victim-app",
      "version": "1.0.0",
      "dependencies": {
        "sha1-hulud-payload": "1.2.3"
      }
    },
    "node_modules/sha1-hulud-payload": {
      "name": "sha1-hulud-payload",
      "version": "1.2.3",
      "integrity": "sha512-visible-install-script-fixture",
      "hasInstallScript": true
    }
  }
}"#,
    )
    .unwrap();

    let recipe = tight_recipe(fs::canonicalize(temp.path()).unwrap().as_path());
    let report = scanner::scan_recipe(
        &recipe,
        offline_scan_request(),
        fs::canonicalize(temp.path()).unwrap().as_path(),
    )
    .await
    .unwrap();
    let categories = finding_categories(&report);

    assert!(categories.contains("sbom-lifecycle-script"));
    assert!(
        report
            .vulnerability_assessments
            .iter()
            .any(|candidate| candidate.vulnerability == "fulcr-SBOM-LIFECYCLE-SCRIPT")
    );

    let decision = gate::evaluate_gate(&recipe, None, Some(&report), &[]);
    assert_eq!(decision.outcome, GateOutcome::Denied);
    assert!(
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("sbom-lifecycle-script"))
    );
}

#[tokio::test]
async fn contains_token_harvesting_and_self_publish_script_metadata() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        fs::canonicalize(temp.path())
            .unwrap()
            .as_path()
            .join("package.json"),
        r#"{
  "name": "tainted-release-package",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node postinstall.js",
    "prepare": "npm token list && npm publish --access public"
  },
  "dependencies": {
    "left-pad": "1.3.0"
  }
}"#,
    )
    .unwrap();
    fs::write(
        fs::canonicalize(temp.path())
            .unwrap()
            .as_path()
            .join("postinstall.js"),
        "console.log(process.env.NPM_TOKEN || process.env.GITHUB_TOKEN);\n",
    )
    .unwrap();

    let recipe = tight_recipe(fs::canonicalize(temp.path()).unwrap().as_path());
    let report = scanner::scan_recipe(
        &recipe,
        offline_scan_request(),
        fs::canonicalize(temp.path()).unwrap().as_path(),
    )
    .await
    .unwrap();
    let categories = finding_categories(&report);

    assert!(categories.contains("sbom-lifecycle-script"));
    assert!(categories.contains("sbom-suspicious-package-script"));

    let decision = gate::evaluate_gate(&recipe, None, Some(&report), &[]);
    assert_eq!(decision.outcome, GateOutcome::Denied);
    assert!(
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("sbom-suspicious-package-script"))
    );
}

#[tokio::test]
async fn blocks_historical_replay_when_provenance_is_weak() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        fs::canonicalize(temp.path())
            .unwrap()
            .as_path()
            .join("package.json"),
        "{\"name\":\"victim-app\"}\n",
    )
    .unwrap();

    let recipe = Recipe::new(RecipeInput {
        name: "victim-app".to_string(),
        source: SourceRef {
            repo: "https://example.invalid/victim-app.git".to_string(),
            revision: "main".to_string(),
            path: Some(
                fs::canonicalize(temp.path())
                    .unwrap()
                    .as_path()
                    .to_path_buf(),
            ),
        },
        builder: BuilderRef {
            kind: BuilderKind::Script,
            name: Some("npm-ci-builder".to_string()),
            digest: None,
        },
        build: Default::default(),
        materials: Vec::new(),
        crypto: Vec::new(),
        policy: Default::default(),
        annotations: Default::default(),
    })
    .unwrap();

    let report = scanner::scan_recipe(
        &recipe,
        offline_scan_request(),
        fs::canonicalize(temp.path()).unwrap().as_path(),
    )
    .await
    .unwrap();
    let decision = gate::evaluate_gate(&recipe, None, Some(&report), &[]);

    assert_eq!(decision.outcome, GateOutcome::Denied);
    assert!(
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("slsa-unpinned-source"))
    );
    assert!(
        decision
            .reasons
            .iter()
            .any(|reason| reason.contains("slsa-unpinned-builder"))
    );
}

fn tight_recipe(source_path: &std::path::Path) -> Recipe {
    Recipe::new(RecipeInput {
        name: "victim-app".to_string(),
        source: SourceRef {
            repo: "https://example.invalid/victim-app.git".to_string(),
            revision: IMMUTABLE_REVISION.to_string(),
            path: Some(source_path.to_path_buf()),
        },
        builder: BuilderRef {
            kind: BuilderKind::Script,
            name: Some("npm-ci-builder".to_string()),
            digest: Some(BUILDER_DIGEST.to_string()),
        },
        build: Default::default(),
        materials: Vec::new(),
        crypto: Vec::new(),
        policy: Default::default(),
        annotations: Default::default(),
    })
    .unwrap()
}

fn finding_categories(report: &fulcr::models::ScanReport) -> BTreeSet<&str> {
    report
        .findings
        .iter()
        .map(|finding| finding.category.as_str())
        .collect()
}

fn offline_scan_request() -> ScanRequest {
    ScanRequest {
        osv_mode: OsvMode::Disabled,
        ..Default::default()
    }
}
