use std::{
    path::{Component, Path as FsPath, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use axum::{
    body::Body,
    extract::{Path, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use futures_util::stream;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::{
    fs,
    io::{AsyncRead, AsyncReadExt},
};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use uuid::Uuid;

use crate::{
    digest::{cache_file_name, digest_bytes},
    gate,
    metadata::{
        attestation_document, cbom_document, openvex_document, sbom_document,
        slsa_provenance_document,
    },
    models::{
        oci_image_config_bytes, oci_image_config_bytes_for_layers, timestamp,
        timestamp_after_seconds, ArtifactRef, BuildRecord, BuildRequest, BuildStatus, GateDecision,
        GateOutcome, Recipe, RecipeInput, ScanReport, ScanRequest, VexInput, VexStatement,
    },
    scanner,
    store::Store,
};

const BUILD_OUTPUT_LIMIT_BYTES: usize = 64 * 1024;
const BUILD_TIMEOUT_SECONDS: u64 = 15 * 60;
const MAX_LAYER_ARTIFACT_BYTES: u64 = 1_073_741_824;
const OCI_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";

#[derive(Clone)]
pub struct AppState {
    store: Store,
    work_dir: PathBuf,
    auth_token: Option<Arc<String>>,
}

pub fn router(store: Store, work_dir: PathBuf) -> Router {
    router_with_auth(
        store,
        work_dir,
        std::env::var("fulcr_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty()),
    )
}

pub fn router_with_auth(store: Store, work_dir: PathBuf, auth_token: Option<String>) -> Router {
    let auth_token = auth_token.filter(|token| !token.trim().is_empty());
    if auth_token.is_none() {
        tracing::warn!(
            "fulcr_TOKEN is not set; protected endpoints will reject requests until a bearer token is configured."
        );
    }
    let state = AppState {
        store,
        work_dir,
        auth_token: auth_token.map(Arc::new),
    };

    let cors = CorsLayer::new()
        .allow_methods([Method::GET, Method::HEAD, Method::POST])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
        .allow_origin(AllowOrigin::list([
            HeaderValue::from_static("http://127.0.0.1"),
            HeaderValue::from_static("http://localhost"),
        ]));

    Router::new()
        .route("/healthz", get(healthz))
        .route("/v2/", get(oci_health).head(oci_health))
        .route(
            "/v2/*path",
            get(oci_distribution).head(oci_distribution_head),
        )
        .route("/v1/recipes", get(list_recipes).post(create_recipe))
        .route("/v1/recipes/:id", get(get_recipe))
        .route(
            "/v1/recipes/:id/builds",
            get(list_builds).post(create_build),
        )
        .route("/v1/recipes/:id/scans", get(list_scans).post(create_scan))
        .route("/v1/recipes/:id/scans/:scan_id", get(get_scan))
        .route("/v1/recipes/:id/gate", get(get_gate))
        .route("/v1/recipes/:id/sbom", get(get_sbom))
        .route("/v1/recipes/:id/cbom", get(get_cbom))
        .route("/v1/recipes/:id/vex", get(get_vex).post(add_vex))
        .route("/v1/recipes/:id/openvex", get(get_openvex))
        .route("/v1/recipes/:id/slsa", get(get_slsa))
        .route("/v1/recipes/:id/attestation", get(get_attestation))
        .layer(middleware::from_fn_with_state(state.clone(), require_auth))
        .layer(cors)
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn require_auth(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let method = request.method();
    let path = request.uri().path();

    let needs_auth = request_needs_auth(method, path);

    if !needs_auth {
        return next.run(request).await;
    }

    let Some(expected) = state.auth_token.as_ref() else {
        return unauthorized_response("fulcr_TOKEN is required for protected endpoints");
    };

    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim);

    match presented {
        Some(token) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => {
            next.run(request).await
        }
        _ => unauthorized_response("missing or invalid bearer token"),
    }
}

fn unauthorized_response(message: impl Into<String>) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Bearer realm="fulcr""#),
    );
    (
        StatusCode::UNAUTHORIZED,
        headers,
        Json(json!({ "error": message.into() })),
    )
        .into_response()
}

fn request_needs_auth(method: &Method, path: &str) -> bool {
    let mutating = matches!(
        method,
        &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE
    );
    let oci_content = path.starts_with("/v2/") && path != "/v2/";
    let metadata_api = path.starts_with("/v1/");

    mutating || oci_content || metadata_api
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

async fn healthz() -> Json<serde_json::Value> {
    Json(json!({"status":"ok"}))
}

async fn oci_health() -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Docker-Distribution-Api-Version",
        HeaderValue::from_static("registry/2.0"),
    );
    (StatusCode::OK, headers).into_response()
}

async fn oci_referrers_response(
    name: String,
    digest: String,
    state: AppState,
    include_body: bool,
) -> AppResult<Response> {
    use oci_spec::image::{DescriptorBuilder, ImageIndexBuilder, MediaType};

    let mut recipe_with_subject = None;
    for candidate in state.store.list_recipes().await? {
        if candidate.name != name {
            continue;
        }
        if candidate.digest == digest {
            let subject = MetadataSubject::recipe(&candidate);
            recipe_with_subject = Some((candidate, subject));
            break;
        }
        if let Ok(manifest) = materialized_image_manifest(&state, &candidate).await {
            if manifest.digest == digest {
                let subject = MetadataSubject::image(&manifest);
                recipe_with_subject = Some((candidate, subject));
                break;
            }
        }
    }
    let Some((recipe, subject)) = recipe_with_subject else {
        return Err(AppError::not_found(format!(
            "referrers for {name}@{digest} not found"
        )));
    };
    let documents = metadata_documents(&state, &recipe, &subject).await?;
    let mut descriptors = Vec::new();
    for document in documents {
        let annotations = std::collections::HashMap::from([
            (
                "org.opencontainers.image.title".to_string(),
                document.title.to_string(),
            ),
            ("dev.fulcr.endpoint".to_string(), document.endpoint.clone()),
        ]);
        descriptors.push(
            DescriptorBuilder::default()
                .media_type(MediaType::ArtifactManifest)
                .artifact_type(MediaType::Other(document.artifact_type.to_string()))
                .digest(parse_oci_digest(&document.manifest_digest)?)
                .size(document.manifest_bytes.len() as u64)
                .annotations(annotations)
                .build()
                .map_err(|error| AppError::Internal(error.into()))?,
        );
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.oci.image.index.v1+json"),
    );

    let index = ImageIndexBuilder::default()
        .schema_version(2u32)
        .media_type(MediaType::ImageIndex)
        .manifests(descriptors)
        .build()
        .map_err(|error| AppError::Internal(error.into()))?;

    let bytes = serde_json::to_vec(&index)?;
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
    if include_body {
        Ok((headers, bytes).into_response())
    } else {
        Ok((StatusCode::OK, headers).into_response())
    }
}

async fn oci_distribution(
    Path(path): Path<String>,
    State(state): State<AppState>,
) -> AppResult<Response> {
    oci_distribution_response(path, state, true).await
}

async fn oci_distribution_head(
    Path(path): Path<String>,
    State(state): State<AppState>,
) -> AppResult<Response> {
    oci_distribution_response(path, state, false).await
}

async fn oci_distribution_response(
    path: String,
    state: AppState,
    include_body: bool,
) -> AppResult<Response> {
    match parse_oci_route(&path)? {
        OciRoute::Manifest { name, reference } => {
            oci_manifest_response(name, reference, state, include_body).await
        }
        OciRoute::Blob { name, digest } => {
            oci_blob_response(name, digest, state, include_body).await
        }
        OciRoute::Referrers { name, digest } => {
            oci_referrers_response(name, digest, state, include_body).await
        }
    }
}

enum OciRoute {
    Manifest { name: String, reference: String },
    Blob { name: String, digest: String },
    Referrers { name: String, digest: String },
}

fn parse_oci_route(path: &str) -> AppResult<OciRoute> {
    let parts = path
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.len() < 3 {
        return Err(AppError::not_found(format!("OCI route {path} not found")));
    }

    let name = parts[..parts.len() - 2].join("/");
    let selector = parts[parts.len() - 2];
    let value = parts[parts.len() - 1].to_string();
    if name.is_empty() || value.is_empty() {
        return Err(AppError::not_found(format!("OCI route {path} not found")));
    }

    match selector {
        "manifests" => Ok(OciRoute::Manifest {
            name,
            reference: value,
        }),
        "blobs" => Ok(OciRoute::Blob {
            name,
            digest: value,
        }),
        "referrers" => Ok(OciRoute::Referrers {
            name,
            digest: value,
        }),
        _ => Err(AppError::not_found(format!("OCI route {path} not found"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_multi_segment_oci_manifest_route() {
        match parse_oci_route("team/platform/service/manifests/v1").unwrap() {
            OciRoute::Manifest { name, reference } => {
                assert_eq!(name, "team/platform/service");
                assert_eq!(reference, "v1");
            }
            _ => panic!("expected manifest route"),
        }
    }

    #[test]
    fn parses_multi_segment_oci_blob_route() {
        match parse_oci_route("team/platform/service/blobs/sha256:abc").unwrap() {
            OciRoute::Blob { name, digest } => {
                assert_eq!(name, "team/platform/service");
                assert_eq!(digest, "sha256:abc");
            }
            _ => panic!("expected blob route"),
        }
    }

    #[test]
    fn parses_multi_segment_oci_referrers_route() {
        match parse_oci_route("team/platform/service/referrers/sha256:abc").unwrap() {
            OciRoute::Referrers { name, digest } => {
                assert_eq!(name, "team/platform/service");
                assert_eq!(digest, "sha256:abc");
            }
            _ => panic!("expected referrers route"),
        }
    }

    #[test]
    fn auth_required_for_mutations_and_oci_content_not_health() {
        assert!(request_needs_auth(&Method::POST, "/v1/recipes"));
        assert!(request_needs_auth(
            &Method::GET,
            "/v2/service/manifests/latest"
        ));
        assert!(request_needs_auth(
            &Method::HEAD,
            "/v2/service/blobs/sha256:abc"
        ));
        assert!(request_needs_auth(&Method::GET, "/v1/recipes"));
        assert!(!request_needs_auth(&Method::GET, "/v2/"));
        assert!(!request_needs_auth(&Method::GET, "/healthz"));
    }

    #[test]
    fn unauthorized_response_advertises_bearer_auth() {
        let response = unauthorized_response("missing token");

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            r#"Bearer realm="fulcr""#
        );
    }

    #[tokio::test]
    async fn blob_route_denies_cached_layer_when_gate_denies() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).await.unwrap();
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: crate::models::SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: None,
            },
            builder: crate::models::BuilderRef {
                kind: crate::models::BuilderKind::Script,
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
        store.save_recipe(&recipe).await.unwrap();

        let bytes = fixture_layer_bytes();
        let digest = digest_bytes(&bytes);
        let cache_path = store.cache_dir().join(cache_file_name(&digest));
        tokio::fs::write(&cache_path, &bytes).await.unwrap();
        store
            .save_build(&BuildRecord {
                id: Uuid::new_v4(),
                recipe_id: recipe.id,
                recipe_digest: recipe.digest.clone(),
                status: BuildStatus::Succeeded,
                created_at: timestamp(),
                started_at: Some(timestamp()),
                finished_at: Some(timestamp()),
                command: Vec::new(),
                working_dir: None,
                exit_code: Some(0),
                artifact: Some(ArtifactRef {
                    digest: digest.clone(),
                    diff_id: Some(digest.clone()),
                    media_type: Some(OCI_LAYER_MEDIA_TYPE.to_string()),
                    size: bytes.len() as u64,
                    retained: true,
                    path: Some(cache_path),
                    expires_at: None,
                }),
                stdout_tail: None,
                stderr_tail: None,
                security_anomalies: Vec::new(),
                notes: Vec::new(),
            })
            .await
            .unwrap();

        let state = AppState {
            store,
            work_dir: temp.path().to_path_buf(),
            auth_token: None,
        };

        match oci_blob_response("service".to_string(), digest, state, true).await {
            Err(AppError::Forbidden(message)) => {
                assert!(message.contains("metadata gate denied pull"));
            }
            other => panic!("expected forbidden blob response, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn execute_native_caps_stdout() {
        let command = format!("printf '%*s' {} ''", BUILD_OUTPUT_LIMIT_BYTES + 1024);
        let (exit_code, stdout, stderr, anomalies) = execute_native(
            vec!["/bin/sh".to_string(), "-c".to_string(), command],
            Vec::new(),
            ".",
            false,
            false,
        )
        .await
        .unwrap();

        assert_eq!(exit_code, 0);
        assert_eq!(stdout.len(), BUILD_OUTPUT_LIMIT_BYTES);
        assert!(String::from_utf8_lossy(&stderr).contains("stdout exceeded output capture limit"));
        assert!(anomalies.is_empty());
    }

    #[tokio::test]
    async fn read_artifact_ref_rejects_non_tar_layer_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = std::fs::canonicalize(temp.path()).unwrap();
        tokio::fs::write(work_dir.join("artifact.bin"), b"not a tar layer")
            .await
            .unwrap();
        let store = Store::open(temp.path().join("store")).await.unwrap();
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: crate::models::SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: Some(work_dir.clone()),
            },
            builder: crate::models::BuilderRef {
                kind: crate::models::BuilderKind::Script,
                name: Some("local".to_string()),
                digest: Some(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                ),
            },
            build: crate::models::BuildSpec {
                artifact: Some(PathBuf::from("artifact.bin")),
                ..Default::default()
            },
            materials: Vec::new(),
            crypto: Vec::new(),
            policy: Default::default(),
            annotations: Default::default(),
        })
        .unwrap();
        let state = AppState {
            store,
            work_dir: work_dir.clone(),
            auth_token: None,
        };
        let mut status = BuildStatus::Succeeded;
        let mut notes = Vec::new();

        let artifact = read_artifact_ref(
            &state,
            &recipe,
            &BuildRequest::default(),
            &work_dir,
            &mut status,
            &mut notes,
        )
        .await
        .unwrap();

        assert!(artifact.is_none());
        assert!(matches!(status, BuildStatus::Failed));
        assert!(notes
            .iter()
            .any(|note| note.contains("not a valid uncompressed OCI layer tar")));
    }

    #[tokio::test]
    async fn validate_oci_layer_tar_file_rejects_parent_path_entry() {
        let temp = tempfile::tempdir().unwrap();
        let layer = temp.path().join("layer.tar");
        {
            let file = std::fs::File::create(&layer).unwrap();
            let mut archive = tar::Builder::new(file);
            let payload = b"escape";
            let mut header = tar::Header::new_gnu();
            let unsafe_path = b"../escape.txt";
            header.as_mut_bytes()[..unsafe_path.len()].copy_from_slice(unsafe_path);
            header.set_size(payload.len() as u64);
            header.set_cksum();
            archive.append(&header, &payload[..]).unwrap();
            archive.finish().unwrap();
        }
        let size = std::fs::metadata(&layer).unwrap().len();

        let error = validate_oci_layer_tar_file(&layer, size)
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsafe layer tar entry path"));
    }

    #[tokio::test]
    async fn validate_oci_layer_tar_file_rejects_unsafe_hard_link_target() {
        let temp = tempfile::tempdir().unwrap();
        let layer = temp.path().join("layer.tar");
        {
            let file = std::fs::File::create(&layer).unwrap();
            let mut archive = tar::Builder::new(file);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_path("safe-link").unwrap();
            header.set_link_name("../escape.txt").unwrap();
            header.set_size(0);
            header.set_cksum();
            archive.append(&header, std::io::empty()).unwrap();
            archive.finish().unwrap();
        }
        let size = std::fs::metadata(&layer).unwrap().len();

        let error = validate_oci_layer_tar_file(&layer, size)
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("unsafe layer tar hard link target"));
    }

    #[test]
    fn uncompressed_layer_diff_id_must_match_blob_digest() {
        let artifact = ArtifactRef {
            digest: format!("sha256:{}", "1".repeat(64)),
            diff_id: Some(format!("sha256:{}", "2".repeat(64))),
            media_type: Some(OCI_LAYER_MEDIA_TYPE.to_string()),
            size: 0,
            retained: true,
            path: None,
            expires_at: None,
        };

        let error = match validated_layer_diff_id(&artifact) {
            Ok(_) => panic!("expected mismatched diff_id to be rejected"),
            Err(AppError::Forbidden(message)) => message,
            Err(other) => panic!("expected forbidden error, got {other:?}"),
        };

        assert!(error.contains("does not match blob digest"));
    }

    #[tokio::test]
    async fn metadata_documents_are_served_by_digest() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).await.unwrap();
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: crate::models::SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: None,
            },
            builder: crate::models::BuilderRef {
                kind: crate::models::BuilderKind::Script,
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
        store.save_recipe(&recipe).await.unwrap();
        let state = AppState {
            store,
            work_dir: temp.path().to_path_buf(),
            auth_token: None,
        };
        let referrers_response = oci_referrers_response(
            "service".to_string(),
            recipe.digest.clone(),
            state.clone(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(referrers_response.status(), StatusCode::OK);

        let head_response = oci_referrers_response(
            "service".to_string(),
            recipe.digest.clone(),
            state.clone(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(head_response.status(), StatusCode::OK);

        let recipe_subject = MetadataSubject::recipe(&recipe);
        let document = metadata_documents(&state, &recipe, &recipe_subject)
            .await
            .unwrap()
            .into_iter()
            .find(|document| document.title == "sbom")
            .unwrap();

        let manifest_response = oci_manifest_response(
            "service".to_string(),
            document.manifest_digest.clone(),
            state.clone(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(manifest_response.status(), StatusCode::OK);

        let response =
            oci_blob_response("service".to_string(), document.digest.clone(), state, true)
                .await
                .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn referrers_are_available_for_image_manifest_digest() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).await.unwrap();
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: crate::models::SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: None,
            },
            builder: crate::models::BuilderRef {
                kind: crate::models::BuilderKind::Script,
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
        store.save_recipe(&recipe).await.unwrap();

        let bytes = fixture_layer_bytes();
        let digest = digest_bytes(&bytes);
        let cache_path = store.cache_dir().join(cache_file_name(&digest));
        tokio::fs::write(&cache_path, &bytes).await.unwrap();
        store
            .save_build(&BuildRecord {
                id: Uuid::new_v4(),
                recipe_id: recipe.id,
                recipe_digest: recipe.digest.clone(),
                status: BuildStatus::Succeeded,
                created_at: timestamp(),
                started_at: Some(timestamp()),
                finished_at: Some(timestamp()),
                command: Vec::new(),
                working_dir: None,
                exit_code: Some(0),
                artifact: Some(ArtifactRef {
                    digest: digest.clone(),
                    diff_id: Some(digest.clone()),
                    media_type: Some(OCI_LAYER_MEDIA_TYPE.to_string()),
                    size: bytes.len() as u64,
                    retained: true,
                    path: Some(cache_path),
                    expires_at: None,
                }),
                stdout_tail: None,
                stderr_tail: None,
                security_anomalies: Vec::new(),
                notes: Vec::new(),
            })
            .await
            .unwrap();
        store
            .save_scan(&ScanReport {
                id: Uuid::new_v4(),
                recipe_id: recipe.id,
                recipe_digest: recipe.digest.clone(),
                created_at: timestamp(),
                scanner: "test".to_string(),
                mode: crate::models::ScanMode::Source,
                root: temp.path().to_path_buf(),
                image: None,
                status: crate::models::ScanStatus::Completed,
                summary: crate::models::ScanSummary::default(),
                components: Vec::new(),
                crypto: Vec::new(),
                binaries: Vec::new(),
                findings: Vec::new(),
                vex_candidates: Vec::new(),
                sbom: crate::metadata::sbom_document(&recipe),
                cbom: crate::metadata::cbom_document(&recipe),
            })
            .await
            .unwrap();

        let state = AppState {
            store,
            work_dir: temp.path().to_path_buf(),
            auth_token: None,
        };
        let manifest_response = oci_manifest_response(
            "service".to_string(),
            recipe.digest.clone(),
            state.clone(),
            true,
        )
        .await
        .unwrap();
        let image_digest = manifest_response
            .headers()
            .get("Docker-Content-Digest")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let referrers_response = oci_referrers_response(
            "service".to_string(),
            image_digest.clone(),
            state.clone(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(referrers_response.status(), StatusCode::OK);

        let image_manifest = materialized_image_manifest(&state, &recipe).await.unwrap();
        assert_eq!(image_manifest.digest, image_digest);
        let image_subject = MetadataSubject::image(&image_manifest);
        let document = metadata_documents(&state, &recipe, &image_subject)
            .await
            .unwrap()
            .into_iter()
            .find(|document| document.title == "sbom")
            .unwrap();
        let artifact_manifest: serde_json::Value =
            serde_json::from_slice(&document.manifest_bytes).unwrap();
        assert_eq!(
            artifact_manifest["subject"]["mediaType"],
            "application/vnd.oci.image.manifest.v1+json"
        );
        assert_eq!(artifact_manifest["subject"]["digest"], image_digest);
        assert_eq!(
            artifact_manifest["subject"]["size"].as_u64(),
            Some(image_manifest.bytes.len() as u64)
        );
        let artifact_manifest_response =
            oci_manifest_response("service".to_string(), document.manifest_digest, state, true)
                .await
                .unwrap();
        assert_eq!(artifact_manifest_response.status(), StatusCode::OK);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pull_manifest_requires_existing_retained_layer() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = std::fs::canonicalize(temp.path()).unwrap();
        let layer_bytes = fixture_layer_bytes();
        tokio::fs::write(work_dir.join("layer.tar"), &layer_bytes)
            .await
            .unwrap();
        let store = Store::open(temp.path().join("store")).await.unwrap();
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: crate::models::SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: Some(work_dir.clone()),
            },
            builder: crate::models::BuilderRef {
                kind: crate::models::BuilderKind::Script,
                name: Some("local".to_string()),
                digest: Some(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                ),
            },
            build: crate::models::BuildSpec {
                command: vec!["/bin/sh".to_string(), "-c".to_string(), ":".to_string()],
                artifact: Some(PathBuf::from("layer.tar")),
                ..Default::default()
            },
            materials: Vec::new(),
            crypto: Vec::new(),
            policy: Default::default(),
            annotations: Default::default(),
        })
        .unwrap();
        store.save_recipe(&recipe).await.unwrap();
        store
            .save_scan(&ScanReport {
                id: Uuid::new_v4(),
                recipe_id: recipe.id,
                recipe_digest: recipe.digest.clone(),
                created_at: timestamp(),
                scanner: "test".to_string(),
                mode: crate::models::ScanMode::Source,
                root: work_dir.clone(),
                image: None,
                status: crate::models::ScanStatus::Completed,
                summary: crate::models::ScanSummary::default(),
                components: Vec::new(),
                crypto: Vec::new(),
                binaries: Vec::new(),
                findings: Vec::new(),
                vex_candidates: Vec::new(),
                sbom: crate::metadata::sbom_document(&recipe),
                cbom: crate::metadata::cbom_document(&recipe),
            })
            .await
            .unwrap();

        let state = AppState {
            store,
            work_dir,
            auth_token: None,
        };
        match oci_manifest_response(
            "service".to_string(),
            recipe.digest.clone(),
            state.clone(),
            false,
        )
        .await
        {
            Err(AppError::Forbidden(message)) => {
                assert!(message.contains("no successful retained build artifact"));
            }
            other => panic!("expected forbidden manifest response, got {other:?}"),
        }

        let builds = state.store.list_builds(recipe.id).await.unwrap();
        assert!(builds.is_empty());
        assert!(!state
            .store
            .cache_dir()
            .join(cache_file_name(&digest_bytes(&layer_bytes)))
            .exists());
    }

    #[tokio::test]
    async fn planned_build_does_not_shadow_retained_layer() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).await.unwrap();
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: crate::models::SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: None,
            },
            builder: crate::models::BuilderRef {
                kind: crate::models::BuilderKind::Script,
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
        store.save_recipe(&recipe).await.unwrap();

        let bytes = fixture_layer_bytes();
        let digest = digest_bytes(&bytes);
        let cache_path = store.cache_dir().join(cache_file_name(&digest));
        tokio::fs::write(&cache_path, &bytes).await.unwrap();
        store
            .save_build(&BuildRecord {
                id: Uuid::new_v4(),
                recipe_id: recipe.id,
                recipe_digest: recipe.digest.clone(),
                status: BuildStatus::Succeeded,
                created_at: timestamp(),
                started_at: Some(timestamp()),
                finished_at: Some(timestamp()),
                command: Vec::new(),
                working_dir: None,
                exit_code: Some(0),
                artifact: Some(ArtifactRef {
                    digest: digest.clone(),
                    diff_id: Some(digest.clone()),
                    media_type: Some(OCI_LAYER_MEDIA_TYPE.to_string()),
                    size: bytes.len() as u64,
                    retained: true,
                    path: Some(cache_path),
                    expires_at: None,
                }),
                stdout_tail: None,
                stderr_tail: None,
                security_anomalies: Vec::new(),
                notes: Vec::new(),
            })
            .await
            .unwrap();
        store
            .save_build(&BuildRecord::planned(&recipe))
            .await
            .unwrap();
        store
            .save_scan(&ScanReport {
                id: Uuid::new_v4(),
                recipe_id: recipe.id,
                recipe_digest: recipe.digest.clone(),
                created_at: timestamp(),
                scanner: "test".to_string(),
                mode: crate::models::ScanMode::Source,
                root: temp.path().to_path_buf(),
                image: None,
                status: crate::models::ScanStatus::Completed,
                summary: crate::models::ScanSummary::default(),
                components: Vec::new(),
                crypto: Vec::new(),
                binaries: Vec::new(),
                findings: Vec::new(),
                vex_candidates: Vec::new(),
                sbom: crate::metadata::sbom_document(&recipe),
                cbom: crate::metadata::cbom_document(&recipe),
            })
            .await
            .unwrap();

        let state = AppState {
            store,
            work_dir: temp.path().to_path_buf(),
            auth_token: None,
        };
        let manifest_response = oci_manifest_response(
            "service".to_string(),
            recipe.digest.clone(),
            state.clone(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(manifest_response.status(), StatusCode::OK);

        let decision = metadata_gate(&state, &recipe).await.unwrap();
        assert_eq!(decision.outcome, GateOutcome::Allowed);
    }

    #[tokio::test]
    async fn layer_artifact_size_rejects_oversized_file() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("oversized-layer.tar");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_LAYER_ARTIFACT_BYTES + 512).unwrap();

        let error = layer_artifact_size(&path).await.unwrap_err().to_string();

        assert!(error.contains("exceeding limit"));
    }

    #[test]
    fn resolve_working_dir_anchors_relative_source_path_under_work_dir() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = std::fs::canonicalize(temp.path()).unwrap();
        std::fs::create_dir_all(work_dir.join("checkout/service")).unwrap();
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: crate::models::SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: Some(PathBuf::from("checkout")),
            },
            builder: crate::models::BuilderRef {
                kind: crate::models::BuilderKind::Script,
                name: Some("local".to_string()),
                digest: Some(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                ),
            },
            build: crate::models::BuildSpec {
                working_dir: Some(PathBuf::from("service")),
                ..Default::default()
            },
            materials: Vec::new(),
            crypto: Vec::new(),
            policy: Default::default(),
            annotations: Default::default(),
        })
        .unwrap();

        let resolved = resolve_working_dir(&recipe, &work_dir).unwrap();

        assert_eq!(resolved, work_dir.join("checkout/service"));
    }

    fn fixture_layer_bytes() -> Vec<u8> {
        let mut bytes = Vec::new();
        {
            let mut archive = tar::Builder::new(&mut bytes);
            let payload = b"hello";
            let mut header = tar::Header::new_gnu();
            header.set_path("hello.txt").unwrap();
            header.set_size(payload.len() as u64);
            header.set_cksum();
            archive.append(&header, &payload[..]).unwrap();
            archive.finish().unwrap();
        }
        bytes
    }
}

async fn list_recipes(State(state): State<AppState>) -> AppResult<Json<Vec<Recipe>>> {
    Ok(Json(state.store.list_recipes().await?))
}

async fn create_recipe(
    State(state): State<AppState>,
    Json(input): Json<RecipeInput>,
) -> AppResult<impl IntoResponse> {
    if input.name.trim().is_empty() {
        return Err(AppError::bad_request("recipe name must not be empty"));
    }
    if input.source.revision.trim().is_empty() {
        return Err(AppError::bad_request("source revision must not be empty"));
    }
    if input.build.run_command.is_some() {
        return Err(AppError::bad_request(
            "build.run_command requires an enforced native sandbox and is not supported yet",
        ));
    }

    let recipe = Recipe::new(input)?;
    state.store.save_recipe(&recipe).await?;
    Ok((StatusCode::CREATED, Json(recipe)))
}

async fn get_recipe(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> AppResult<Json<Recipe>> {
    Ok(Json(load_recipe(&state, id).await?))
}

async fn list_builds(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> AppResult<Json<Vec<BuildRecord>>> {
    load_recipe(&state, id).await?;
    Ok(Json(state.store.list_builds(id).await?))
}

async fn create_build(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(request): Json<BuildRequest>,
) -> AppResult<impl IntoResponse> {
    let recipe = load_recipe(&state, id).await?;
    let record = if request.execute {
        enforce_build_gate(&state, &recipe).await?;
        execute_build(&state, &recipe, request).await?
    } else {
        BuildRecord::planned(&recipe)
    };

    state.store.save_build(&record).await?;
    Ok((StatusCode::CREATED, Json(record)))
}

async fn get_sbom(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    let recipe = load_recipe(&state, id).await?;
    if let Some(scan) = state.store.latest_scan(id).await? {
        return Ok(Json(scan.sbom));
    }
    Ok(Json(sbom_document(&recipe)))
}

async fn get_cbom(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    let recipe = load_recipe(&state, id).await?;
    if let Some(scan) = state.store.latest_scan(id).await? {
        return Ok(Json(scan.cbom));
    }
    Ok(Json(cbom_document(&recipe)))
}

async fn list_scans(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> AppResult<Json<Vec<ScanReport>>> {
    load_recipe(&state, id).await?;
    Ok(Json(state.store.list_scans(id).await?))
}

async fn get_scan(
    Path((id, scan_id)): Path<(Uuid, Uuid)>,
    State(state): State<AppState>,
) -> AppResult<Json<ScanReport>> {
    load_recipe(&state, id).await?;
    let scan = state
        .store
        .get_scan(id, scan_id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("scan {scan_id} not found")))?;
    Ok(Json(scan))
}

async fn create_scan(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(request): Json<ScanRequest>,
) -> AppResult<impl IntoResponse> {
    let recipe = load_recipe(&state, id).await?;
    let scan = scanner::scan_recipe(&recipe, request, &state.work_dir).await?;
    state.store.save_scan(&scan).await?;
    Ok((StatusCode::CREATED, Json(scan)))
}

async fn get_gate(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> AppResult<Json<GateDecision>> {
    let recipe = load_recipe(&state, id).await?;
    let builds = state.store.list_builds(id).await?;
    let latest_scan = state.store.latest_scan(id).await?;
    let vex = state.store.list_vex(id).await?;
    Ok(Json(gate::evaluate_gate(
        &recipe,
        latest_build_evidence(&builds),
        latest_scan.as_ref(),
        &vex,
    )))
}

async fn add_vex(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
    Json(input): Json<VexInput>,
) -> AppResult<impl IntoResponse> {
    let recipe = load_recipe(&state, id).await?;
    if input.vulnerability.trim().is_empty() {
        return Err(AppError::bad_request("vulnerability must not be empty"));
    }
    match input.recipe_digest.as_deref() {
        Some(declared) if declared == recipe.digest => {}
        Some(other) => {
            return Err(AppError::bad_request(format!(
                "vex.recipe_digest {other} does not match current recipe digest {}",
                recipe.digest
            )));
        }
        None => {
            return Err(AppError::bad_request(
                "vex.recipe_digest is required and must equal the current recipe digest",
            ));
        }
    }
    let statement = VexStatement::new(id, recipe.digest.clone(), input);
    state.store.save_vex_statement(&statement).await?;
    Ok((StatusCode::CREATED, Json(statement)))
}

async fn get_vex(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> AppResult<Json<Vec<VexStatement>>> {
    load_recipe(&state, id).await?;
    Ok(Json(state.store.list_vex(id).await?))
}

async fn get_openvex(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    let recipe = load_recipe(&state, id).await?;
    let statements = state.store.list_vex(id).await?;
    Ok(Json(openvex_document(&recipe, &statements)))
}

async fn get_attestation(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    let recipe = load_recipe(&state, id).await?;
    let builds = state.store.list_builds(id).await?;
    let vex = state.store.list_vex(id).await?;
    Ok(Json(attestation_document(
        &recipe,
        latest_build_evidence(&builds),
        &vex,
    )?))
}

async fn get_slsa(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    let recipe = load_recipe(&state, id).await?;
    let builds = state.store.list_builds(id).await?;
    let latest_scan = state.store.latest_scan(id).await?;
    let vex = state.store.list_vex(id).await?;
    Ok(Json(slsa_provenance_document(
        &recipe,
        latest_build_evidence(&builds),
        latest_scan.as_ref(),
        &vex,
    )?))
}

async fn oci_manifest_response(
    name: String,
    reference: String,
    state: AppState,
    include_body: bool,
) -> AppResult<Response> {
    if let Some(document) = metadata_artifact_manifest_by_digest(&state, &name, &reference).await? {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/vnd.oci.artifact.manifest.v1+json"),
        );
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from(document.manifest_bytes.len()),
        );
        headers.insert(
            "Docker-Content-Digest",
            header_value(&document.manifest_digest)?,
        );
        return if include_body {
            Ok((headers, document.manifest_bytes).into_response())
        } else {
            Ok((StatusCode::OK, headers).into_response())
        };
    }

    let recipe = if let Ok(id) = Uuid::parse_str(&reference) {
        state.store.get_recipe(id).await?.filter(|r| r.name == name)
    } else {
        state.store.lookup_recipe(&name, &reference).await?
    };

    let recipe = recipe
        .ok_or_else(|| AppError::not_found(format!("manifest {name}:{reference} not found")))?;

    let manifest = materialized_image_manifest(&state, &recipe).await?;

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.oci.image.manifest.v1+json"),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from(manifest.bytes.len()),
    );
    headers.insert("Docker-Content-Digest", header_value(&manifest.digest)?);

    if include_body {
        Ok((headers, manifest.bytes).into_response())
    } else {
        Ok((StatusCode::OK, headers).into_response())
    }
}

struct MaterializedImageManifest {
    digest: String,
    bytes: Vec<u8>,
}

async fn materialized_image_manifest(
    state: &AppState,
    recipe: &Recipe,
) -> AppResult<MaterializedImageManifest> {
    enforce_manifest_gate(state, recipe).await?;

    let layer = latest_materialized_layer(state, recipe).await?;
    materialized_image_manifest_for_layer(recipe, &layer)
}

fn materialized_image_manifest_for_layer(
    recipe: &Recipe,
    layer: &ArtifactRef,
) -> AppResult<MaterializedImageManifest> {
    let diff_ids = vec![validated_layer_diff_id(layer)?];
    let config = oci_image_config_bytes_for_layers(recipe, &diff_ids)?;
    let config_digest = digest_bytes(&config);

    parse_oci_digest(&config_digest)?;
    parse_oci_digest(&layer.digest)?;
    let retention = if recipe.policy.retain_artifact {
        "selective"
    } else {
        "ephemeral"
    };
    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": config_digest,
            "size": config.len() as u64
        },
        "layers": [{
            "mediaType": OCI_LAYER_MEDIA_TYPE,
            "digest": layer.digest,
            "size": layer.size
        }],
        "annotations": {
            "org.opencontainers.image.source": recipe.source.repo.clone(),
            "org.opencontainers.image.revision": recipe.source.revision.clone(),
            "dev.fulcr.materialized": "true",
            "dev.fulcr.retention": retention,
            "dev.fulcr.note": "approved retained layer artifact; source and metadata remain the registry source of truth"
        }
    });
    let bytes = serde_json::to_vec(&manifest)?;
    let digest = digest_bytes(&bytes);
    Ok(MaterializedImageManifest { digest, bytes })
}

async fn oci_blob_response(
    name: String,
    digest: String,
    state: AppState,
    include_body: bool,
) -> AppResult<Response> {
    if let Some(recipe_id) = state.store.lookup_blob_recipe(&digest).await {
        if let Some(recipe) = state.store.get_recipe(recipe_id).await? {
            let config = oci_image_config_bytes(&recipe)?;
            // Re-verify the digest to defend against index drift.
            if recipe.name == name && crate::digest::digest_bytes(&config) == digest {
                enforce_manifest_gate(&state, &recipe).await?;
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/vnd.oci.image.config.v1+json"),
                );
                headers.insert(header::CONTENT_LENGTH, HeaderValue::from(config.len()));
                headers.insert("Docker-Content-Digest", header_value(&digest)?);
                return if include_body {
                    Ok((headers, config).into_response())
                } else {
                    Ok((StatusCode::OK, headers).into_response())
                };
            }
        }
    }

    for recipe in state.store.list_recipes().await? {
        if recipe.name != name {
            continue;
        }
        if let Ok(layer) = latest_materialized_layer(&state, &recipe).await {
            let diff_ids = vec![validated_layer_diff_id(&layer)?];
            let config = oci_image_config_bytes_for_layers(&recipe, &diff_ids)?;
            if crate::digest::digest_bytes(&config) == digest {
                enforce_manifest_gate(&state, &recipe).await?;
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/vnd.oci.image.config.v1+json"),
                );
                headers.insert(header::CONTENT_LENGTH, HeaderValue::from(config.len()));
                headers.insert("Docker-Content-Digest", header_value(&digest)?);
                return if include_body {
                    Ok((headers, config).into_response())
                } else {
                    Ok((StatusCode::OK, headers).into_response())
                };
            }

            if layer.digest == digest {
                enforce_manifest_gate(&state, &recipe).await?;
                let Some(path) = layer.path.as_ref() else {
                    return Err(AppError::not_found(format!("blob {digest} not found")));
                };
                let size = validate_layer_artifact_file(path, &layer.digest, layer.size)
                    .await
                    .map_err(|_| AppError::not_found(format!("blob {digest} not found")))?;
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/octet-stream"),
                );
                headers.insert(header::CONTENT_LENGTH, HeaderValue::from(size));
                headers.insert("Docker-Content-Digest", header_value(&digest)?);
                return if include_body {
                    let file = fs::File::open(path)
                        .await
                        .map_err(|_| AppError::not_found(format!("blob {digest} not found")))?;
                    Ok((headers, file_body(file)).into_response())
                } else {
                    Ok((StatusCode::OK, headers).into_response())
                };
            }
        }

        if let Some(document) = metadata_document_by_digest(&state, &recipe, &digest).await? {
            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, header_value(document.artifact_type)?);
            headers.insert(
                header::CONTENT_LENGTH,
                HeaderValue::from(document.bytes.len()),
            );
            headers.insert("Docker-Content-Digest", header_value(&document.digest)?);
            return if include_body {
                Ok((headers, document.bytes).into_response())
            } else {
                Ok((StatusCode::OK, headers).into_response())
            };
        }
    }

    Err(AppError::not_found(format!("blob {digest} not found")))
}

struct MetadataDocument {
    title: &'static str,
    artifact_type: &'static str,
    endpoint: String,
    digest: String,
    bytes: Vec<u8>,
    manifest_digest: String,
    manifest_bytes: Vec<u8>,
}

struct MetadataSubject {
    media_type: &'static str,
    digest: String,
    size: u64,
}

impl MetadataSubject {
    fn recipe(recipe: &Recipe) -> Self {
        Self {
            media_type: "application/vnd.fulcr.recipe.v1+json",
            digest: recipe.digest.clone(),
            size: 0,
        }
    }

    fn image(manifest: &MaterializedImageManifest) -> Self {
        Self {
            media_type: "application/vnd.oci.image.manifest.v1+json",
            digest: manifest.digest.clone(),
            size: manifest.bytes.len() as u64,
        }
    }
}

async fn metadata_documents(
    state: &AppState,
    recipe: &Recipe,
    subject: &MetadataSubject,
) -> AppResult<Vec<MetadataDocument>> {
    let builds = state.store.list_builds(recipe.id).await?;
    let latest_scan = state.store.latest_scan(recipe.id).await?;
    let vex = state.store.list_vex(recipe.id).await?;
    let sbom = latest_scan
        .as_ref()
        .map(|scan| scan.sbom.clone())
        .unwrap_or_else(|| sbom_document(recipe));
    let sbom_artifact_type = if sbom.get("spdxVersion").is_some() {
        "application/spdx+json"
    } else {
        "application/vnd.cyclonedx+json"
    };
    let cbom = latest_scan
        .as_ref()
        .map(|scan| scan.cbom.clone())
        .unwrap_or_else(|| cbom_document(recipe));

    let values = [
        (
            "sbom",
            sbom_artifact_type,
            format!("/v1/recipes/{}/sbom", recipe.id),
            sbom,
        ),
        (
            "cbom",
            "application/vnd.fulcr.cbom+json",
            format!("/v1/recipes/{}/cbom", recipe.id),
            cbom,
        ),
        (
            "openvex",
            "application/openvex+json",
            format!("/v1/recipes/{}/openvex", recipe.id),
            openvex_document(recipe, &vex),
        ),
        (
            "slsa",
            "application/vnd.in-toto+json",
            format!("/v1/recipes/{}/slsa", recipe.id),
            slsa_provenance_document(
                recipe,
                latest_build_evidence(&builds),
                latest_scan.as_ref(),
                &vex,
            )?,
        ),
        (
            "attestation",
            "application/vnd.fulcr.attestation+json",
            format!("/v1/recipes/{}/attestation", recipe.id),
            attestation_document(recipe, latest_build_evidence(&builds), &vex)?,
        ),
    ];

    let mut documents = Vec::new();
    for (title, artifact_type, endpoint, value) in values {
        let bytes = serde_json::to_vec(&value)?;
        let digest = digest_bytes(&bytes);
        let manifest = json!({
            "mediaType": "application/vnd.oci.artifact.manifest.v1+json",
            "artifactType": artifact_type,
            "blobs": [{
                "mediaType": artifact_type,
                "digest": digest,
                "size": bytes.len() as u64,
                "annotations": {
                    "org.opencontainers.image.title": title
                }
            }],
            "subject": {
                "mediaType": subject.media_type,
                "digest": subject.digest,
                "size": subject.size
            },
            "annotations": {
                "org.opencontainers.image.title": title,
                "dev.fulcr.endpoint": endpoint.clone()
            }
        });
        let manifest_bytes = serde_json::to_vec(&manifest)?;
        let manifest_digest = digest_bytes(&manifest_bytes);
        documents.push(MetadataDocument {
            title,
            artifact_type,
            endpoint,
            digest,
            bytes,
            manifest_digest,
            manifest_bytes,
        });
    }
    Ok(documents)
}

async fn metadata_document_by_digest(
    state: &AppState,
    recipe: &Recipe,
    digest: &str,
) -> AppResult<Option<MetadataDocument>> {
    Ok(
        metadata_documents(state, recipe, &MetadataSubject::recipe(recipe))
            .await?
            .into_iter()
            .find(|document| document.digest == digest),
    )
}

async fn metadata_artifact_manifest_by_digest(
    state: &AppState,
    name: &str,
    digest: &str,
) -> AppResult<Option<MetadataDocument>> {
    for recipe in state.store.list_recipes().await? {
        if recipe.name != name {
            continue;
        }
        let mut subjects = vec![MetadataSubject::recipe(&recipe)];
        if let Ok(manifest) = materialized_image_manifest(state, &recipe).await {
            subjects.push(MetadataSubject::image(&manifest));
        }
        for subject in subjects {
            if let Some(document) = metadata_documents(state, &recipe, &subject)
                .await?
                .into_iter()
                .find(|document| document.manifest_digest == digest)
            {
                return Ok(Some(document));
            }
        }
    }
    Ok(None)
}

fn parse_oci_digest(digest: &str) -> AppResult<oci_spec::image::Digest> {
    digest
        .parse::<oci_spec::image::Digest>()
        .map_err(|error| AppError::Internal(error.into()))
}

fn header_value(value: &str) -> AppResult<HeaderValue> {
    HeaderValue::from_str(value).map_err(|error| AppError::Internal(error.into()))
}

async fn latest_materialized_layer(state: &AppState, recipe: &Recipe) -> AppResult<ArtifactRef> {
    let builds = state.store.list_builds(recipe.id).await?;
    let Some(build) = builds
        .into_iter()
        .rev()
        .find(|build| !matches!(build.status, BuildStatus::Planned))
    else {
        return Err(AppError::forbidden(
            "metadata gate allowed pull, but no successful retained build artifact is available",
        ));
    };
    if !matches!(build.status, BuildStatus::Succeeded) {
        return Err(AppError::forbidden(format!(
            "metadata gate allowed pull, but latest build {} is not successful",
            build.id
        )));
    }
    let Some(artifact) = build.artifact else {
        return Err(AppError::forbidden(format!(
            "metadata gate allowed pull, but latest build {} has no materialized artifact",
            build.id
        )));
    };
    if !artifact.retained {
        return Err(AppError::forbidden(format!(
            "metadata gate allowed pull, but latest build {} discarded its artifact",
            build.id
        )));
    }
    let Some(path) = artifact.path.as_ref() else {
        return Err(AppError::forbidden(format!(
            "metadata gate allowed pull, but latest build {} artifact has no cache path",
            build.id
        )));
    };
    if let Err(error) = validate_layer_artifact_file(path, &artifact.digest, artifact.size).await {
        return Err(AppError::forbidden(format!(
            "metadata gate allowed pull, but cached artifact for build {} is invalid: {error}",
            build.id
        )));
    }
    Ok(artifact)
}

async fn load_recipe(state: &AppState, id: Uuid) -> AppResult<Recipe> {
    state
        .store
        .get_recipe(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("recipe {id} not found")))
}

async fn enforce_build_gate(state: &AppState, recipe: &Recipe) -> AppResult<()> {
    let decision = metadata_gate(state, recipe).await?;
    if decision.outcome == GateOutcome::Denied {
        return Err(AppError::forbidden(format!(
            "metadata gate denied build: {}",
            decision.reasons.join("; ")
        )));
    }
    Ok(())
}

async fn enforce_manifest_gate(state: &AppState, recipe: &Recipe) -> AppResult<()> {
    let decision = metadata_gate(state, recipe).await?;
    if decision.outcome == GateOutcome::Denied {
        return Err(AppError::forbidden(format!(
            "metadata gate denied pull: {}",
            decision.reasons.join("; ")
        )));
    }
    Ok(())
}

async fn metadata_gate(state: &AppState, recipe: &Recipe) -> AppResult<GateDecision> {
    let builds = state.store.list_builds(recipe.id).await?;
    let latest_scan = state.store.latest_scan(recipe.id).await?;
    let vex = state.store.list_vex(recipe.id).await?;
    Ok(gate::evaluate_gate(
        recipe,
        latest_build_evidence(&builds),
        latest_scan.as_ref(),
        &vex,
    ))
}

fn latest_build_evidence(builds: &[BuildRecord]) -> Option<&BuildRecord> {
    builds
        .iter()
        .rev()
        .find(|build| !matches!(build.status, BuildStatus::Planned))
}

async fn execute_native(
    cmd: Vec<String>,
    env: Vec<String>,
    working_dir: &str,
    network_disabled: bool,
    monitor_security: bool,
) -> anyhow::Result<(i64, Vec<u8>, Vec<u8>, Vec<String>)> {
    if cmd.is_empty() {
        return Err(anyhow::anyhow!("empty command"));
    }

    if network_disabled {
        return Err(anyhow::anyhow!(
            "network-disabled execution requires an enforced native sandbox"
        ));
    }

    let mut command = tokio::process::Command::new(&cmd[0]);
    command.args(&cmd[1..]);
    command.current_dir(working_dir);

    // Provide env vars
    command.env_clear();
    for e in env {
        if let Some((k, v)) = e.split_once('=') {
            command.env(k, v);
        }
    }

    // Capture output
    command.stdout(std::process::Stdio::piped());
    command.stderr(std::process::Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn: {}", e))?;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to capture stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("failed to capture stderr"))?;
    let stdout_task = tokio::spawn(read_capped(stdout, BUILD_OUTPUT_LIMIT_BYTES));
    let stderr_task = tokio::spawn(read_capped(stderr, BUILD_OUTPUT_LIMIT_BYTES));

    let status = match tokio::time::timeout(
        std::time::Duration::from_secs(BUILD_TIMEOUT_SECONDS),
        child.wait(),
    )
    .await
    {
        Ok(result) => result.map_err(|e| anyhow::anyhow!("failed to wait: {}", e))?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            return Err(anyhow::anyhow!(
                "command timed out after {BUILD_TIMEOUT_SECONDS} seconds"
            ));
        }
    };

    let exit_code = status.code().unwrap_or(1) as i64;
    let (stdout_buf, stdout_truncated) = stdout_task
        .await
        .map_err(|e| anyhow::anyhow!("stdout reader failed: {}", e))?
        .map_err(|e| anyhow::anyhow!("stdout read failed: {}", e))?;
    let (mut stderr_buf, stderr_truncated) = stderr_task
        .await
        .map_err(|e| anyhow::anyhow!("stderr reader failed: {}", e))?
        .map_err(|e| anyhow::anyhow!("stderr read failed: {}", e))?;
    if stdout_truncated {
        stderr_buf.extend_from_slice(b"\n[fulcr] stdout exceeded output capture limit\n");
    }
    if stderr_truncated {
        stderr_buf.extend_from_slice(b"\n[fulcr] stderr exceeded output capture limit\n");
    }
    let mut anomalies = Vec::new();

    // Security monitoring on output
    if monitor_security {
        let out_str = String::from_utf8_lossy(&stdout_buf);
        let err_str = String::from_utf8_lossy(&stderr_buf);
        for s in out_str.lines().chain(err_str.lines()) {
            if s.contains("curl ")
                || s.contains("wget ")
                || s.contains("chmod ")
                || s.contains("nc ")
            {
                let warn = format!(
                    "[SECURITY WARN] Suspicious runtime activity detected: {}",
                    s
                );
                println!("{}", warn);
                anomalies.push(s.trim().to_string());
            }
        }
    }

    Ok((exit_code, stdout_buf, stderr_buf, anomalies))
}

async fn read_capped<R: AsyncRead + Unpin>(
    mut reader: R,
    cap: usize,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut output = Vec::new();
    let mut truncated = false;
    let mut buffer = [0_u8; 8192];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        let remaining = cap.saturating_sub(output.len());
        if remaining > 0 {
            output.extend_from_slice(&buffer[..read.min(remaining)]);
        }
        if read > remaining {
            truncated = true;
        }
    }
    Ok((output, truncated))
}

async fn execute_build(
    state: &AppState,
    recipe: &Recipe,
    request: BuildRequest,
) -> AppResult<BuildRecord> {
    if recipe.build.command.is_empty() {
        return Err(AppError::bad_request("recipe build command is empty"));
    }
    if recipe.build.run_command.is_some() {
        return Err(AppError::bad_request(
            "build.run_command requires an enforced native sandbox and is not supported yet",
        ));
    }

    let started_at = timestamp();
    let working_dir = resolve_working_dir(recipe, &state.work_dir)?;
    let mut notes = Vec::new();

    let env: Vec<String> = request
        .environment
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();

    // 1. Build Phase (network allowed)
    let (build_exit, mut stdout_buf, mut stderr_buf, mut all_anomalies) = execute_native(
        recipe.build.command.clone(),
        env.clone(),
        &working_dir.to_string_lossy(),
        false, // network_disabled = false
        false, // monitor_security = false
    )
    .await
    .unwrap_or_else(|error| {
        notes.push(format!("build command failed before completion: {error}"));
        (
            1,
            Vec::new(),
            format!("build command failed before completion: {error}\n").into_bytes(),
            Vec::new(),
        )
    });

    let mut exit_code = Some(build_exit);

    // 2. Run / Scan Phase. Fail closed unless network isolation is actually enforced.
    if build_exit == 0 {
        if let Some(run_cmd) = &recipe.build.run_command {
            stdout_buf.extend_from_slice(
                b"
--- RUN PHASE ---
",
            );
            stderr_buf.extend_from_slice(
                b"
--- RUN PHASE ---
",
            );

            match execute_native(
                run_cmd.clone(),
                env,
                &working_dir.to_string_lossy(),
                true, // network_disabled = true
                true, // monitor_security = true
            )
            .await
            {
                Ok((run_exit, run_stdout, run_stderr, run_anomalies)) => {
                    exit_code = Some(run_exit);
                    stdout_buf.extend_from_slice(&run_stdout);
                    stderr_buf.extend_from_slice(&run_stderr);
                    all_anomalies.extend(run_anomalies);
                }
                Err(error) => {
                    exit_code = Some(1);
                    notes.push(format!("run command refused: {error}"));
                    stderr_buf
                        .extend_from_slice(format!("run command refused: {error}\n").as_bytes());
                }
            }
        }
    }

    let mut status = if exit_code.unwrap_or(1) == 0 {
        BuildStatus::Succeeded
    } else {
        BuildStatus::Failed
    };

    let artifact = read_artifact_ref(
        state,
        recipe,
        &request,
        &working_dir,
        &mut status,
        &mut notes,
    )
    .await?;

    let record = BuildRecord {
        id: Uuid::new_v4(),
        recipe_id: recipe.id,
        recipe_digest: recipe.digest.clone(),
        status,
        created_at: started_at.clone(),
        started_at: Some(started_at),
        finished_at: Some(timestamp()),
        command: recipe.build.command.clone(),
        working_dir: Some(working_dir),
        exit_code: exit_code.map(|c| c as i32),
        artifact,
        stdout_tail: Some(tail_lossy(&stdout_buf, 4096)),
        stderr_tail: Some(tail_lossy(&stderr_buf, 4096)),
        security_anomalies: all_anomalies,
        notes,
    };

    Ok(record)
}

async fn read_artifact_ref(
    state: &AppState,
    recipe: &Recipe,
    request: &BuildRequest,
    working_dir: &std::path::Path,
    status: &mut BuildStatus,
    notes: &mut Vec<String>,
) -> AppResult<Option<ArtifactRef>> {
    let Some(artifact) = &recipe.build.artifact else {
        notes.push("no artifact path declared; build output was not fingerprinted".to_string());
        return Ok(None);
    };

    if artifact.is_absolute()
        || artifact.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        *status = BuildStatus::Failed;
        notes.push(format!(
            "declared artifact path is not a safe relative path: {}",
            artifact.display()
        ));
        return Ok(None);
    }

    let artifact_path = working_dir.join(artifact);
    // Canonicalize and re-check containment so that any in-tree symlink cannot escape
    // the recipe's working directory and turn this read into an arbitrary-file disclosure.
    let canonical = match std::fs::canonicalize(&artifact_path) {
        Ok(path) => path,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            *status = BuildStatus::Failed;
            notes.push(format!(
                "declared artifact was not found: {}",
                artifact_path.display()
            ));
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    if !canonical.starts_with(working_dir) {
        *status = BuildStatus::Failed;
        notes.push(format!(
            "declared artifact escapes the recipe working directory: {}",
            canonical.display()
        ));
        return Ok(None);
    }

    let size = match layer_artifact_size(&canonical).await {
        Ok(size) => size,
        Err(error) => {
            *status = BuildStatus::Failed;
            notes.push(format!(
                "declared artifact is too large or unreadable: {error}"
            ));
            return Ok(None);
        }
    };
    if let Err(error) = validate_oci_layer_tar_file(&canonical, size).await {
        *status = BuildStatus::Failed;
        notes.push(format!(
            "declared artifact is not a valid uncompressed OCI layer tar: {error}"
        ));
        return Ok(None);
    }

    let digest = digest_file(&canonical).await?;
    let retained = request.cache_artifact || recipe.policy.retain_artifact;
    let (path, expires_at) = if retained {
        let cache_path = state.store.cache_dir().join(cache_file_name(&digest));
        fs::copy(&canonical, &cache_path).await?;
        let expires_at = if recipe.policy.cache_ttl_seconds == 0 {
            None
        } else {
            Some(timestamp_after_seconds(recipe.policy.cache_ttl_seconds))
        };
        (Some(cache_path), expires_at)
    } else {
        notes
            .push("artifact was fingerprinted and discarded by fulcr retention policy".to_string());
        (None, None)
    };

    Ok(Some(ArtifactRef {
        digest: digest.clone(),
        diff_id: Some(digest),
        media_type: Some(OCI_LAYER_MEDIA_TYPE.to_string()),
        size,
        retained,
        path,
        expires_at,
    }))
}

fn validated_layer_diff_id(artifact: &ArtifactRef) -> AppResult<String> {
    match (artifact.diff_id.as_deref(), artifact.media_type.as_deref()) {
        (Some(diff_id), Some(OCI_LAYER_MEDIA_TYPE)) if diff_id == artifact.digest => {
            Ok(diff_id.to_string())
        }
        (Some(diff_id), Some(OCI_LAYER_MEDIA_TYPE)) => Err(AppError::forbidden(format!(
            "retained uncompressed layer diff_id {diff_id} does not match blob digest {}",
            artifact.digest
        ))),
        (Some(_), Some(media_type)) => Err(AppError::forbidden(format!(
            "retained artifact has unsupported OCI layer media type {media_type}"
        ))),
        _ => Err(AppError::forbidden(
            "retained artifact lacks OCI layer diff_id or media_type metadata",
        )),
    }
}

async fn validate_layer_artifact_file(
    path: &FsPath,
    expected_digest: &str,
    expected_size: u64,
) -> anyhow::Result<u64> {
    let size = layer_artifact_size(path).await?;
    if size != expected_size {
        anyhow::bail!("layer artifact size changed: expected {expected_size}, found {size}");
    }
    let digest = digest_file(path).await?;
    if digest != expected_digest {
        anyhow::bail!("layer artifact digest changed: expected {expected_digest}, found {digest}");
    }
    validate_oci_layer_tar_file(path, size).await?;
    Ok(size)
}

fn file_body(file: fs::File) -> Body {
    Body::from_stream(stream::try_unfold(file, |mut file| async move {
        let mut buffer = vec![0_u8; 8192];
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            Ok::<_, std::io::Error>(None)
        } else {
            buffer.truncate(read);
            Ok::<_, std::io::Error>(Some((buffer, file)))
        }
    }))
}

async fn layer_artifact_size(path: &FsPath) -> anyhow::Result<u64> {
    let size = fs::metadata(path)
        .await
        .with_context(|| format!("reading metadata for {}", path.display()))?
        .len();
    if size > MAX_LAYER_ARTIFACT_BYTES {
        anyhow::bail!(
            "layer artifact is {size} bytes, exceeding limit of {MAX_LAYER_ARTIFACT_BYTES} bytes"
        );
    }
    Ok(size)
}

async fn digest_file(path: &FsPath) -> anyhow::Result<String> {
    let mut file = fs::File::open(path)
        .await
        .with_context(|| format!("opening {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .with_context(|| format!("reading {}", path.display()))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("sha256:{}", hex::encode(digest.finalize())))
}

async fn validate_oci_layer_tar_file(path: &FsPath, size: u64) -> anyhow::Result<()> {
    if size < 1024 || !size.is_multiple_of(512) {
        anyhow::bail!("layer tar is not 512-byte block aligned or lacks end markers");
    }

    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> anyhow::Result<()> {
        let file = std::fs::File::open(&path)
            .with_context(|| format!("opening layer tar {}", path.display()))?;
        let mut archive = tar::Archive::new(file);
        for entry in archive.entries().context("reading layer tar entries")? {
            let entry = entry.context("reading layer tar entry")?;
            let entry_path = entry
                .path()
                .context("reading layer tar entry path")?
                .into_owned();
            validate_safe_layer_tar_path(&entry_path, "layer tar entry path")?;

            let entry_type = entry.header().entry_type();
            if entry_type.is_hard_link() {
                let Some(link_name) = entry
                    .link_name()
                    .context("reading layer tar hard link target")?
                else {
                    anyhow::bail!(
                        "layer tar hard link missing target at {}",
                        entry_path.display()
                    );
                };
                validate_safe_layer_tar_path(&link_name, "layer tar hard link target")?;
                continue;
            }
            if entry_type.is_symlink() {
                continue;
            }
            if !entry_type.is_file() && !entry_type.is_dir() {
                anyhow::bail!(
                    "unsupported layer tar entry type at {}",
                    entry_path.display()
                );
            }
        }
        Ok(())
    })
    .await
    .context("layer tar validator failed")??;
    Ok(())
}

fn validate_safe_layer_tar_path(path: &FsPath, description: &str) -> anyhow::Result<()> {
    let mut has_normal_component = false;
    for component in path.components() {
        match component {
            Component::Normal(_) => has_normal_component = true,
            Component::CurDir => {}
            _ => anyhow::bail!("unsafe {description}: {}", path.display()),
        }
    }
    if !has_normal_component {
        anyhow::bail!("unsafe {description}: {}", path.display());
    }
    Ok(())
}

fn resolve_working_dir(recipe: &Recipe, work_dir: &FsPath) -> anyhow::Result<PathBuf> {
    let work_dir = std::fs::canonicalize(work_dir)
        .with_context(|| format!("canonicalizing work dir {}", work_dir.display()))?;
    let source_dir = recipe
        .source
        .path
        .as_deref()
        .map(|path| anchor_under(path, &work_dir))
        .unwrap_or_else(|| work_dir.clone());
    let mut dir = source_dir;
    if let Some(path) = &recipe.build.working_dir {
        if path.is_absolute() {
            dir = path.clone();
        } else {
            dir.push(path);
        }
    }
    let canon = std::fs::canonicalize(&dir)?;
    if !canon.starts_with(&work_dir) {
        anyhow::bail!("working directory escapes the configured work dir");
    }
    Ok(canon)
}

fn anchor_under(path: &FsPath, base: &FsPath) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn tail_lossy(bytes: &[u8], max: usize) -> String {
    let lossy = String::from_utf8_lossy(bytes);
    if lossy.len() <= max {
        lossy.into_owned()
    } else {
        let start = lossy.floor_char_boundary(lossy.len() - max);
        lossy[start..].to_string()
    }
}

type AppResult<T> = Result<T, AppError>;

#[derive(Debug)]
enum AppError {
    BadRequest(String),
    Forbidden(String),
    NotFound(String),
    Internal(anyhow::Error),
}

impl AppError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self::BadRequest(message.into())
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self::Forbidden(message.into())
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self::NotFound(message.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, message),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, message),
            Self::Internal(error) => {
                tracing::error!(?error, "internal error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal server error".to_string(),
                )
            }
        };

        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl From<anyhow::Error> for AppError {
    fn from(error: anyhow::Error) -> Self {
        Self::Internal(error)
    }
}

impl From<std::io::Error> for AppError {
    fn from(error: std::io::Error) -> Self {
        Self::Internal(error.into())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(error: serde_json::Error) -> Self {
        Self::Internal(error.into())
    }
}
