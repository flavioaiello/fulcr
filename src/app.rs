use std::{
    path::{Component, Path as FsPath, PathBuf},
    sync::Arc,
};

use anyhow::Context;
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use futures_util::stream;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::{fs, io::AsyncReadExt};
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
};
use uuid::Uuid;

use crate::{
    digest::{cache_file_name, digest_bytes},
    gate,
    metadata::{
        attestation_document, cbom_document, combined_vex_statements, openvex_document,
        sbom_document, scan_evidence_digest, slsa_provenance_document,
    },
    models::{
        ArtifactRef, BuildRecord, BuildRequest, BuildStatus, GateDecision, GateOutcome, Recipe,
        RecipeInput, ScanReport, ScanRequest, VexInput, VexStatement, oci_image_config_bytes,
        oci_image_config_bytes_for_layers, timestamp, timestamp_after_seconds,
    },
    scanner,
    store::Store,
};

const MAX_LAYER_ARTIFACT_BYTES: u64 = 1_073_741_824;
const OCI_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_EMPTY_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";
const OCI_EMPTY_CONFIG_BYTES: &[u8] = b"{}";

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
        std::env::var("FULCR_TOKEN")
            .ok()
            .filter(|token| !token.trim().is_empty()),
    )
}

pub fn router_with_auth(store: Store, work_dir: PathBuf, auth_token: Option<String>) -> Router {
    let auth_token = auth_token.filter(|token| !token.trim().is_empty());
    if auth_token.is_none() {
        tracing::warn!(
            "FULCR_TOKEN is not set; protected endpoints will reject requests until a token is configured."
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
            "/v2/{*path}",
            get(oci_distribution).head(oci_distribution_head),
        )
        .route("/v1/recipes", get(list_recipes).post(create_recipe))
        .route("/v1/recipes/{id}", get(get_recipe))
        .route(
            "/v1/recipes/{id}/builds",
            get(list_builds).post(create_build),
        )
        .route("/v1/recipes/{id}/scans", get(list_scans).post(create_scan))
        .route("/v1/recipes/{id}/scans/{scan_id}", get(get_scan))
        .route("/v1/recipes/{id}/gate", get(get_gate))
        .route("/v1/recipes/{id}/sbom", get(get_sbom))
        .route("/v1/recipes/{id}/cbom", get(get_cbom))
        .route("/v1/recipes/{id}/vex", get(get_vex).post(add_vex))
        .route("/v1/recipes/{id}/openvex", get(get_openvex))
        .route("/v1/recipes/{id}/slsa", get(get_slsa))
        .route("/v1/recipes/{id}/attestation", get(get_attestation))
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

    let oci_request = path.starts_with("/v2/");

    let Some(expected) = state.auth_token.as_ref() else {
        return unauthorized_response(
            "FULCR_TOKEN is required for protected endpoints",
            oci_request,
        );
    };

    let authorization = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let presented = authorization.and_then(presented_token);

    match presented {
        Some(token) if constant_time_eq(token.as_bytes(), expected.as_bytes()) => {
            next.run(request).await
        }
        _ => unauthorized_response("missing or invalid bearer token", oci_request),
    }
}

fn unauthorized_response(message: impl Into<String>, oci: bool) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static(r#"Basic realm="fulcr""#),
    );
    let message = message.into();
    if oci {
        (
            StatusCode::UNAUTHORIZED,
            headers,
            Json(json!({
                "errors": [{ "code": "UNAUTHORIZED", "message": message }]
            })),
        )
            .into_response()
    } else {
        (
            StatusCode::UNAUTHORIZED,
            headers,
            Json(json!({ "error": message })),
        )
            .into_response()
    }
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
    let a = Sha256::digest(a);
    let b = Sha256::digest(b);
    let mut diff = 0_u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

fn presented_token(authorization: &str) -> Option<String> {
    if let Some(token) = authorization.strip_prefix("Bearer ") {
        return Some(token.trim().to_string());
    }
    let encoded = authorization.strip_prefix("Basic ")?.trim();
    let decoded = BASE64_STANDARD.decode(encoded).ok()?;
    let decoded = std::str::from_utf8(&decoded).ok()?;
    let (_, password) = decoded.split_once(':')?;
    Some(password.to_string())
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
        if let Ok(manifest) = materialized_image_manifest(&state, &candidate).await
            && manifest.digest == digest
        {
            let subject = MetadataSubject::image(&manifest);
            recipe_with_subject = Some((candidate, subject));
            break;
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
                .media_type(MediaType::ImageManifest)
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
    let route = parse_oci_route(&path).map_err(|error| error.into_oci("NAME_UNKNOWN"))?;
    let (result, not_found_code) = match route {
        OciRoute::Manifest { name, reference } => (
            oci_manifest_response(name, reference, state, include_body).await,
            "MANIFEST_UNKNOWN",
        ),
        OciRoute::Blob { name, digest } => (
            oci_blob_response(name, digest, state, include_body).await,
            "BLOB_UNKNOWN",
        ),
        OciRoute::Referrers { name, digest } => (
            oci_referrers_response(name, digest, state, include_body).await,
            "MANIFEST_UNKNOWN",
        ),
    };
    result.map_err(|error| error.into_oci(not_found_code))
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
        let response = unauthorized_response("missing token", true);

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.headers().get(header::WWW_AUTHENTICATE).unwrap(),
            r#"Basic realm="fulcr""#
        );
    }

    #[test]
    fn accepts_bearer_and_basic_tokens() {
        assert_eq!(
            presented_token("Bearer secret-token").as_deref(),
            Some("secret-token")
        );
        assert_eq!(
            presented_token("Basic ZnVsY3I6c2VjcmV0LXRva2Vu").as_deref(),
            Some("secret-token")
        );
        assert!(presented_token("Basic not-base64").is_none());
    }

    #[tokio::test]
    async fn external_vex_resolution_is_opt_in_and_fixed_is_machine_only() {
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
                name: Some("external".to_string()),
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

        let disabled = match add_vex(
            Path(recipe.id),
            State(state.clone()),
            Json(external_vex_input(
                &recipe,
                crate::models::VexStatus::NotAffected,
            )),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("external VEX should be disabled"),
        };
        assert!(matches!(disabled, AppError::BadRequest(message) if message.contains("disabled")));

        let fixed = match add_vex(
            Path(recipe.id),
            State(state),
            Json(external_vex_input(&recipe, crate::models::VexStatus::Fixed)),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("external fixed VEX should be rejected"),
        };
        assert!(
            matches!(fixed, AppError::BadRequest(message) if message.contains("derives fixed"))
        );
    }

    #[tokio::test]
    async fn enabled_external_vex_requires_and_persists_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).await.unwrap();
        let policy = crate::models::RetentionPolicy {
            allow_external_vex_overrides: true,
            ..Default::default()
        };
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: crate::models::SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: None,
            },
            builder: crate::models::BuilderRef {
                kind: crate::models::BuilderKind::Script,
                name: Some("external".to_string()),
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
        store.save_recipe(&recipe).await.unwrap();
        store
            .save_build(&external_vex_build(&recipe))
            .await
            .unwrap();
        let state = AppState {
            store,
            work_dir: temp.path().to_path_buf(),
            auth_token: None,
        };
        let mut incomplete = external_vex_input(&recipe, crate::models::VexStatus::NotAffected);
        incomplete.author = None;
        let error = match add_vex(Path(recipe.id), State(state.clone()), Json(incomplete)).await {
            Err(error) => error,
            Ok(_) => panic!("incomplete external VEX should be rejected"),
        };
        assert!(matches!(error, AppError::BadRequest(message) if message.contains("requires")));

        let mut wrong_subject = external_vex_input(&recipe, crate::models::VexStatus::NotAffected);
        wrong_subject.product = Some(format!("urn:oci:blob:sha256:{}", "e".repeat(64)));
        let error = match add_vex(Path(recipe.id), State(state.clone()), Json(wrong_subject)).await
        {
            Err(error) => error,
            Ok(_) => panic!("wrong-subject external VEX should be rejected"),
        };
        assert!(
            matches!(error, AppError::BadRequest(message) if message.contains("product must equal"))
        );

        let mut expired = external_vex_input(&recipe, crate::models::VexStatus::NotAffected);
        expired.expires_at = Some("2000-01-01T00:00:00Z".to_string());
        let error = match add_vex(Path(recipe.id), State(state.clone()), Json(expired)).await {
            Err(error) => error,
            Ok(_) => panic!("expired external VEX should be rejected"),
        };
        assert!(matches!(error, AppError::BadRequest(message) if message.contains("future")));

        let _ = add_vex(
            Path(recipe.id),
            State(state.clone()),
            Json(external_vex_input(
                &recipe,
                crate::models::VexStatus::NotAffected,
            )),
        )
        .await
        .unwrap()
        .into_response();
        let statements = state.store.list_vex(recipe.id).await.unwrap();
        assert_eq!(statements.len(), 1);
        assert_eq!(
            statements[0].author.as_deref(),
            Some("security@example.invalid")
        );
    }

    fn external_vex_input(recipe: &Recipe, status: crate::models::VexStatus) -> VexInput {
        VexInput {
            vulnerability: "CVE-2026-0001".to_string(),
            status,
            recipe_digest: Some(recipe.digest.clone()),
            product: Some(format!("urn:oci:blob:sha256:{}", "d".repeat(64))),
            component: Some("openssl".to_string()),
            justification: Some("vulnerable_code_not_present".to_string()),
            detail: Some("Administrative exception backed by external evidence".to_string()),
            author: Some("security@example.invalid".to_string()),
            expires_at: Some("2999-01-01T00:00:00Z".to_string()),
        }
    }

    fn external_vex_build(recipe: &Recipe) -> BuildRecord {
        let digest = format!("sha256:{}", "d".repeat(64));
        BuildRecord {
            id: Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            source_scan_id: Some(Uuid::new_v4()),
            source_scan_digest: Some(format!("sha256:{}", "a".repeat(64))),
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
                digest: digest.clone(),
                diff_id: Some(digest),
                media_type: Some(OCI_LAYER_MEDIA_TYPE.to_string()),
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

    #[tokio::test]
    async fn missing_manifest_uses_oci_error_envelope() {
        let temp = tempfile::tempdir().unwrap();
        let state = AppState {
            store: Store::open(temp.path()).await.unwrap(),
            work_dir: temp.path().to_path_buf(),
            auth_token: None,
        };

        let response =
            oci_distribution_response("missing/manifests/latest".to_string(), state, true)
                .await
                .unwrap_err()
                .into_response();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 16 * 1024)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["errors"][0]["code"], "MANIFEST_UNKNOWN");
        assert!(body.get("error").is_none());
    }

    #[tokio::test]
    async fn oci_empty_config_descriptor_resolves_to_blob() {
        let temp = tempfile::tempdir().unwrap();
        let state = AppState {
            store: Store::open(temp.path()).await.unwrap(),
            work_dir: temp.path().to_path_buf(),
            auth_token: None,
        };
        let digest = digest_bytes(OCI_EMPTY_CONFIG_BYTES);

        let response = oci_blob_response("any/repository".to_string(), digest.clone(), state, true)
            .await
            .unwrap();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();

        assert_eq!(headers[header::CONTENT_TYPE], OCI_EMPTY_CONFIG_MEDIA_TYPE);
        assert_eq!(headers["Docker-Content-Digest"], digest);
        assert_eq!(&bytes[..], OCI_EMPTY_CONFIG_BYTES);
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
                source_scan_id: None,
                source_scan_digest: None,
                artifact_scan_id: None,
                policy_decision: None,
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
                    path: Some(cache_path.clone()),
                    expires_at: None,
                }),
                stdout_tail: None,
                stderr_tail: None,
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
        assert!(
            notes
                .iter()
                .any(|note| note.contains("not a valid uncompressed OCI layer tar"))
        );
    }

    #[tokio::test]
    async fn execute_build_imports_artifact_without_running_recipe_command() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = std::fs::canonicalize(temp.path()).unwrap();
        tokio::fs::write(work_dir.join("layer.tar"), fixture_layer_bytes())
            .await
            .unwrap();
        let store = Store::open(work_dir.join("store")).await.unwrap();
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
                command: vec![
                    "/bin/sh".to_string(),
                    "-c".to_string(),
                    "touch command-was-run".to_string(),
                ],
                artifact: Some(PathBuf::from("layer.tar")),
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

        let record = execute_build(
            &state,
            &recipe,
            BuildRequest {
                execute: true,
                cache_artifact: true,
                environment: Default::default(),
                osv_mode: crate::models::OsvMode::Disabled,
            },
        )
        .await
        .unwrap();

        assert!(matches!(record.status, BuildStatus::Succeeded));
        assert!(!work_dir.join("command-was-run").exists());
        assert!(record.command.is_empty());
        let artifact = record.artifact.unwrap();
        assert!(
            artifact
                .path
                .unwrap()
                .metadata()
                .unwrap()
                .permissions()
                .readonly()
        );
    }

    #[tokio::test]
    async fn artifact_ingestion_rejects_existing_cas_digest_mismatch() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = std::fs::canonicalize(temp.path()).unwrap();
        let layer_bytes = fixture_layer_bytes();
        tokio::fs::write(work_dir.join("layer.tar"), &layer_bytes)
            .await
            .unwrap();
        let store = Store::open(work_dir.join("store")).await.unwrap();
        let digest = digest_bytes(&layer_bytes);
        let cache_path = store.cache_dir().join(cache_file_name(&digest));
        let mut different_bytes = layer_bytes.clone();
        let payload_offset = different_bytes
            .windows(b"hello".len())
            .position(|window| window == b"hello")
            .unwrap();
        different_bytes[payload_offset] = b'j';
        tokio::fs::write(&cache_path, &different_bytes)
            .await
            .unwrap();
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
                artifact: Some(PathBuf::from("layer.tar")),
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

        let error = execute_build(
            &state,
            &recipe,
            BuildRequest {
                execute: true,
                cache_artifact: true,
                environment: Default::default(),
                osv_mode: crate::models::OsvMode::Disabled,
            },
        )
        .await
        .unwrap_err();

        assert!(matches!(error, AppError::Internal(_)));
        assert_eq!(tokio::fs::read(cache_path).await.unwrap(), different_bytes);
        assert!(
            !work_dir
                .join("store/cache")
                .read_dir()
                .unwrap()
                .any(|entry| {
                    entry.ok().is_some_and(|entry| {
                        entry.file_name().to_string_lossy().starts_with(".ingest-")
                    })
                })
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retained_layer_selection_rejects_same_size_cas_mutation() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let work_dir = std::fs::canonicalize(temp.path()).unwrap();
        let layer_bytes = fixture_layer_bytes();
        tokio::fs::write(work_dir.join("layer.tar"), &layer_bytes)
            .await
            .unwrap();
        let store = Store::open(work_dir.join("store")).await.unwrap();
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: crate::models::SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: Some(work_dir.clone()),
            },
            builder: crate::models::BuilderRef {
                kind: crate::models::BuilderKind::Script,
                name: Some("external".to_string()),
                digest: Some(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                ),
            },
            build: crate::models::BuildSpec {
                artifact: Some(PathBuf::from("layer.tar")),
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
            work_dir,
            auth_token: None,
        };
        let record = execute_build(
            &state,
            &recipe,
            BuildRequest {
                execute: true,
                cache_artifact: true,
                environment: Default::default(),
                osv_mode: crate::models::OsvMode::Disabled,
            },
        )
        .await
        .unwrap();
        state.store.save_build(&record).await.unwrap();
        let artifact = record.artifact.unwrap();
        let cache_path = artifact.path.unwrap();
        let mut permissions = std::fs::metadata(&cache_path).unwrap().permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&cache_path, permissions).unwrap();
        let mut mutated = layer_bytes;
        let offset = mutated
            .windows(b"hello".len())
            .position(|window| window == b"hello")
            .unwrap();
        mutated[offset] = b'j';
        tokio::fs::write(&cache_path, mutated).await.unwrap();

        let error = latest_materialized_layer(&state, &recipe)
            .await
            .unwrap_err();

        assert!(
            matches!(error, AppError::Forbidden(message) if message.contains("digest mismatch"))
        );
    }

    #[tokio::test]
    async fn build_import_retries_after_failure_and_binds_fresh_scans() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = std::fs::canonicalize(temp.path()).unwrap();
        let source_dir = work_dir.join("source");
        tokio::fs::create_dir(&source_dir).await.unwrap();
        tokio::fs::write(source_dir.join("layer.tar"), b"not a layer")
            .await
            .unwrap();
        let store = Store::open(work_dir.join("store")).await.unwrap();
        let policy = crate::models::RetentionPolicy {
            require_osv: false,
            retain_artifact: true,
            ..Default::default()
        };
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: crate::models::SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: Some(source_dir.clone()),
            },
            builder: crate::models::BuilderRef {
                kind: crate::models::BuilderKind::Script,
                name: Some("external".to_string()),
                digest: Some(
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                ),
            },
            build: crate::models::BuildSpec {
                artifact: Some(PathBuf::from("layer.tar")),
                ..Default::default()
            },
            materials: Vec::new(),
            crypto: Vec::new(),
            policy,
            annotations: Default::default(),
        })
        .unwrap();
        store.save_recipe(&recipe).await.unwrap();
        let state = AppState {
            store,
            work_dir,
            auth_token: None,
        };
        let request = BuildRequest {
            execute: true,
            cache_artifact: true,
            environment: Default::default(),
            osv_mode: crate::models::OsvMode::Disabled,
        };

        let _ = create_build(Path(recipe.id), State(state.clone()), Json(request.clone()))
            .await
            .unwrap()
            .into_response();
        assert!(matches!(
            state.store.list_builds(recipe.id).await.unwrap()[0].status,
            BuildStatus::Failed
        ));

        tokio::fs::write(source_dir.join("layer.tar"), fixture_layer_bytes())
            .await
            .unwrap();
        let _ = create_build(Path(recipe.id), State(state.clone()), Json(request))
            .await
            .unwrap()
            .into_response();

        let builds = state.store.list_builds(recipe.id).await.unwrap();
        let successful = builds.last().unwrap();
        assert!(matches!(successful.status, BuildStatus::Succeeded));
        assert!(successful.source_scan_id.is_some());
        assert!(successful.source_scan_digest.is_some());
        assert_eq!(
            successful
                .policy_decision
                .as_ref()
                .map(|decision| &decision.outcome),
            Some(&GateOutcome::Allowed)
        );
        let latest_scan = state.store.latest_scan(recipe.id).await.unwrap().unwrap();
        assert!(latest_scan.image.as_ref().is_some_and(|image| {
            image.layers.iter().any(|layer| {
                successful
                    .artifact
                    .as_ref()
                    .is_some_and(|artifact| layer.digest == artifact.digest)
            })
        }));
        assert_eq!(successful.artifact_scan_id, Some(latest_scan.id));
        let mut later_source_scan = state
            .store
            .get_scan(recipe.id, successful.source_scan_id.unwrap())
            .await
            .unwrap()
            .unwrap();
        later_source_scan.id = Uuid::new_v4();
        later_source_scan.created_at = timestamp();
        state.store.save_scan(&later_source_scan).await.unwrap();
        let decision_scan = load_decision_scan(&state, recipe.id, Some(successful))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decision_scan.id, latest_scan.id);
        assert_eq!(
            metadata_gate(&state, &recipe).await.unwrap().outcome,
            GateOutcome::Allowed
        );

        let source_scan_id = successful.source_scan_id.unwrap();
        let mut source_scan = state
            .store
            .get_scan(recipe.id, source_scan_id)
            .await
            .unwrap()
            .unwrap();
        source_scan.scanner = "tampered-scanner".to_string();
        state.store.save_scan(&source_scan).await.unwrap();
        let decision = metadata_gate(&state, &recipe).await.unwrap();
        assert_eq!(decision.outcome, GateOutcome::Denied);
        assert!(decision
            .reasons
            .iter()
            .any(|reason| reason.contains("source scan binding") && reason.contains("mismatch")));
        let slsa =
            verified_slsa_provenance_document(&state, &recipe, &builds, Some(&latest_scan), &[])
                .await
                .unwrap();
        assert_eq!(
            slsa["predicate"]["runDetails"]["metadata"]["fulcrSlsaPolicy"]["outcome"],
            "denied"
        );
    }

    #[tokio::test]
    async fn denied_artifact_intake_persists_failed_policy_decision() {
        let temp = tempfile::tempdir().unwrap();
        let work_dir = std::fs::canonicalize(temp.path()).unwrap();
        let source_dir = work_dir.join("source");
        tokio::fs::create_dir(&source_dir).await.unwrap();
        tokio::fs::write(
            source_dir.join("developer.key"),
            "-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n",
        )
        .await
        .unwrap();
        let store = Store::open(work_dir.join("store")).await.unwrap();
        let policy = crate::models::RetentionPolicy {
            require_osv: false,
            retain_artifact: true,
            ..Default::default()
        };
        let recipe = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: crate::models::SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "0123456789abcdef0123456789abcdef01234567".to_string(),
                path: Some(source_dir),
            },
            builder: crate::models::BuilderRef {
                kind: crate::models::BuilderKind::Script,
                name: Some("external".to_string()),
                digest: Some(format!("sha256:{}", "a".repeat(64))),
            },
            build: crate::models::BuildSpec {
                artifact: Some(PathBuf::from("layer.tar")),
                ..Default::default()
            },
            materials: Vec::new(),
            crypto: Vec::new(),
            policy,
            annotations: Default::default(),
        })
        .unwrap();
        store.save_recipe(&recipe).await.unwrap();
        let state = AppState {
            store,
            work_dir,
            auth_token: None,
        };

        let error = match create_build(
            Path(recipe.id),
            State(state.clone()),
            Json(BuildRequest {
                execute: true,
                cache_artifact: true,
                environment: Default::default(),
                osv_mode: crate::models::OsvMode::Disabled,
            }),
        )
        .await
        {
            Err(error) => error,
            Ok(_) => panic!("private key source should deny artifact intake"),
        };
        assert!(
            matches!(error, AppError::Forbidden(message) if message.contains("denied artifact intake"))
        );

        let builds = state.store.list_builds(recipe.id).await.unwrap();
        assert_eq!(builds.len(), 1);
        assert!(matches!(builds[0].status, BuildStatus::Failed));
        assert!(builds[0].source_scan_id.is_some());
        assert_eq!(
            builds[0]
                .policy_decision
                .as_ref()
                .map(|decision| &decision.outcome),
            Some(&GateOutcome::Denied)
        );
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

    #[test]
    fn artifact_expiry_is_enforced_fail_closed() {
        assert!(artifact_is_expired("2000-01-01T00:00:00Z").unwrap());
        assert!(!artifact_is_expired("2999-01-01T00:00:00Z").unwrap());
        assert!(artifact_is_expired("not-a-timestamp").is_err());
    }

    #[tokio::test]
    async fn metadata_documents_are_served_by_digest() {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(temp.path()).await.unwrap();
        let unmaterialized = Recipe::new(RecipeInput {
            name: "service".to_string(),
            source: crate::models::SourceRef {
                repo: "https://example.invalid/service".to_string(),
                revision: "ffffffffffffffffffffffffffffffffffffffff".to_string(),
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
        store.save_recipe(&unmaterialized).await.unwrap();
        let corrupt_scan_dir = temp
            .path()
            .join("scans")
            .join(unmaterialized.id.to_string());
        tokio::fs::create_dir_all(&corrupt_scan_dir).await.unwrap();
        tokio::fs::write(corrupt_scan_dir.join("corrupt.json"), b"not-json")
            .await
            .unwrap();
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
        let (source_scan_id, source_scan_digest) =
            save_fixture_source_scan(&store, &recipe, temp.path()).await;
        store
            .save_build(&BuildRecord {
                id: Uuid::new_v4(),
                recipe_id: recipe.id,
                recipe_digest: recipe.digest.clone(),
                source_scan_id: Some(source_scan_id),
                source_scan_digest: Some(source_scan_digest),
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
                    digest: digest.clone(),
                    diff_id: Some(digest.clone()),
                    media_type: Some(OCI_LAYER_MEDIA_TYPE.to_string()),
                    size: bytes.len() as u64,
                    retained: true,
                    path: Some(cache_path.clone()),
                    expires_at: None,
                }),
                stdout_tail: None,
                stderr_tail: None,
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
                filesystem_digest: None,
                declared_artifact_digest: None,
                mode: crate::models::ScanMode::Filesystem,
                root: temp.path().to_path_buf(),
                image: Some(crate::models::ImageScanMetadata {
                    kind: "oci-layer-artifact".to_string(),
                    archive: cache_path,
                    manifest_digest: None,
                    config_digest: None,
                    tags: Vec::new(),
                    layers: vec![crate::models::ImageLayerMetadata {
                        digest: digest.clone(),
                        diff_id: Some(digest),
                        media_type: Some(OCI_LAYER_MEDIA_TYPE.to_string()),
                        size: bytes.len() as u64,
                    }],
                }),
                status: crate::models::ScanStatus::Completed,
                summary: crate::models::ScanSummary::default(),
                components: Vec::new(),
                crypto: Vec::new(),
                binaries: Vec::new(),
                findings: Vec::new(),
                vulnerability_assessments: Vec::new(),
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
        let image_manifest = materialized_image_manifest(&state, &recipe).await.unwrap();
        let referrers_response = oci_referrers_response(
            "service".to_string(),
            image_manifest.digest.clone(),
            state.clone(),
            true,
        )
        .await
        .unwrap();
        assert_eq!(referrers_response.status(), StatusCode::OK);

        let head_response = oci_referrers_response(
            "service".to_string(),
            image_manifest.digest.clone(),
            state.clone(),
            false,
        )
        .await
        .unwrap();
        assert_eq!(head_response.status(), StatusCode::OK);

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
            artifact_manifest["mediaType"],
            "application/vnd.oci.image.manifest.v1+json"
        );
        assert_eq!(
            artifact_manifest["config"]["mediaType"],
            OCI_EMPTY_CONFIG_MEDIA_TYPE
        );
        assert!(artifact_manifest["layers"].is_array());

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
        let (source_scan_id, source_scan_digest) =
            save_fixture_source_scan(&store, &recipe, temp.path()).await;
        store
            .save_build(&BuildRecord {
                id: Uuid::new_v4(),
                recipe_id: recipe.id,
                recipe_digest: recipe.digest.clone(),
                source_scan_id: Some(source_scan_id),
                source_scan_digest: Some(source_scan_digest),
                artifact_scan_id: None,
                policy_decision: None,
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
                    path: Some(cache_path.clone()),
                    expires_at: None,
                }),
                stdout_tail: None,
                stderr_tail: None,
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
                filesystem_digest: None,
                declared_artifact_digest: None,
                mode: crate::models::ScanMode::Filesystem,
                root: temp.path().to_path_buf(),
                image: Some(crate::models::ImageScanMetadata {
                    kind: "oci-layer-artifact".to_string(),
                    archive: cache_path,
                    manifest_digest: None,
                    config_digest: None,
                    tags: Vec::new(),
                    layers: vec![crate::models::ImageLayerMetadata {
                        digest: digest.clone(),
                        diff_id: Some(digest),
                        media_type: Some(OCI_LAYER_MEDIA_TYPE.to_string()),
                        size: bytes.len() as u64,
                    }],
                }),
                status: crate::models::ScanStatus::Completed,
                summary: crate::models::ScanSummary::default(),
                components: Vec::new(),
                crypto: Vec::new(),
                binaries: Vec::new(),
                findings: Vec::new(),
                vulnerability_assessments: Vec::new(),
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
                filesystem_digest: None,
                declared_artifact_digest: None,
                mode: crate::models::ScanMode::Source,
                root: work_dir.clone(),
                image: None,
                status: crate::models::ScanStatus::Completed,
                summary: crate::models::ScanSummary::default(),
                components: Vec::new(),
                crypto: Vec::new(),
                binaries: Vec::new(),
                findings: Vec::new(),
                vulnerability_assessments: Vec::new(),
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
        assert!(
            !state
                .store
                .cache_dir()
                .join(cache_file_name(&digest_bytes(&layer_bytes)))
                .exists()
        );
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
        let (source_scan_id, source_scan_digest) =
            save_fixture_source_scan(&store, &recipe, temp.path()).await;
        store
            .save_build(&BuildRecord {
                id: Uuid::new_v4(),
                recipe_id: recipe.id,
                recipe_digest: recipe.digest.clone(),
                source_scan_id: Some(source_scan_id),
                source_scan_digest: Some(source_scan_digest),
                artifact_scan_id: None,
                policy_decision: None,
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
                    path: Some(cache_path.clone()),
                    expires_at: None,
                }),
                stdout_tail: None,
                stderr_tail: None,
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
                filesystem_digest: None,
                declared_artifact_digest: None,
                mode: crate::models::ScanMode::Filesystem,
                root: temp.path().to_path_buf(),
                image: Some(crate::models::ImageScanMetadata {
                    kind: "oci-layer-artifact".to_string(),
                    archive: cache_path,
                    manifest_digest: None,
                    config_digest: None,
                    tags: Vec::new(),
                    layers: vec![crate::models::ImageLayerMetadata {
                        digest: digest.clone(),
                        diff_id: Some(digest),
                        media_type: Some(OCI_LAYER_MEDIA_TYPE.to_string()),
                        size: bytes.len() as u64,
                    }],
                }),
                status: crate::models::ScanStatus::Completed,
                summary: crate::models::ScanSummary::default(),
                components: Vec::new(),
                crypto: Vec::new(),
                binaries: Vec::new(),
                findings: Vec::new(),
                vulnerability_assessments: Vec::new(),
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

    async fn save_fixture_source_scan(
        store: &Store,
        recipe: &Recipe,
        root: &std::path::Path,
    ) -> (Uuid, String) {
        let scan = ScanReport {
            id: Uuid::new_v4(),
            recipe_id: recipe.id,
            recipe_digest: recipe.digest.clone(),
            created_at: timestamp(),
            scanner: "test-source-scanner".to_string(),
            filesystem_digest: Some(digest_bytes(&[])),
            declared_artifact_digest: None,
            mode: crate::models::ScanMode::Source,
            root: root.to_path_buf(),
            image: None,
            status: crate::models::ScanStatus::Completed,
            summary: crate::models::ScanSummary::default(),
            components: Vec::new(),
            crypto: Vec::new(),
            binaries: Vec::new(),
            findings: Vec::new(),
            vulnerability_assessments: Vec::new(),
            sbom: crate::metadata::sbom_document(recipe),
            cbom: crate::metadata::cbom_document(recipe),
        };
        let digest = scan_evidence_digest(&scan).unwrap();
        store.save_scan(&scan).await.unwrap();
        (scan.id, digest)
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
    let proposed = Recipe::new(input)?;
    let proposed_id = proposed.id;
    let recipe = state.store.save_recipe(&proposed).await?;
    let status = if recipe.id == proposed_id {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((status, Json(recipe)))
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
    let osv_mode = request.osv_mode.clone();
    let mut source_scan_for_assessment = None;
    let mut record = if request.execute {
        let excluded_roots = [state.store.data_dir().to_path_buf()];
        let source_scan = scanner::scan_recipe_excluding(
            &recipe,
            ScanRequest {
                mode: crate::models::ScanMode::Source,
                path: None,
                max_file_bytes: None,
                osv_mode: osv_mode.clone(),
            },
            &state.work_dir,
            &excluded_roots,
        )
        .await?;
        state.store.save_scan(&source_scan).await?;
        let intake_decision = gate::evaluate_artifact_intake_gate(&recipe, &source_scan);
        if intake_decision.outcome == GateOutcome::Denied {
            let source_scan_digest = scan_evidence_digest(&source_scan)?;
            state
                .store
                .save_build(&BuildRecord {
                    id: Uuid::new_v4(),
                    recipe_id: recipe.id,
                    recipe_digest: recipe.digest.clone(),
                    source_scan_id: Some(source_scan.id),
                    source_scan_digest: Some(source_scan_digest),
                    artifact_scan_id: None,
                    policy_decision: Some(intake_decision.clone()),
                    status: BuildStatus::Failed,
                    created_at: timestamp(),
                    started_at: Some(timestamp()),
                    finished_at: Some(timestamp()),
                    command: Vec::new(),
                    working_dir: None,
                    exit_code: None,
                    artifact: None,
                    stdout_tail: None,
                    stderr_tail: None,
                    notes: vec!["autonomous source policy denied artifact intake".to_string()],
                })
                .await?;
            return Err(AppError::forbidden(format!(
                "metadata gate denied artifact intake: {}",
                intake_decision.reasons.join("; ")
            )));
        }
        let mut record = execute_build(&state, &recipe, request).await?;
        if matches!(record.status, BuildStatus::Succeeded) {
            let imported_artifact_digest = record
                .artifact
                .as_ref()
                .map(|artifact| artifact.digest.as_str())
                .ok_or_else(|| AppError::forbidden("successful import lacks artifact evidence"))?;
            let scanned_artifact_digest = source_scan
                .declared_artifact_digest
                .as_deref()
                .ok_or_else(|| {
                    AppError::forbidden(
                        "fresh source scan did not fingerprint the declared artifact path",
                    )
                })?;
            if imported_artifact_digest != scanned_artifact_digest {
                return Err(AppError::forbidden(format!(
                    "imported artifact digest does not match fresh source scan: expected {}, found {}",
                    scanned_artifact_digest, imported_artifact_digest
                )));
            }
            let expected_source_digest =
                source_scan.filesystem_digest.as_deref().ok_or_else(|| {
                    AppError::forbidden("fresh source scan lacks a filesystem digest")
                })?;
            let actual_source_digest = scanner::source_filesystem_digest_excluding(
                &recipe,
                &state.work_dir,
                &excluded_roots,
            )
            .await?;
            if actual_source_digest != expected_source_digest {
                return Err(AppError::forbidden(format!(
                    "source tree changed during artifact ingestion: expected {}, found {}",
                    expected_source_digest, actual_source_digest
                )));
            }
        }
        record.source_scan_id = Some(source_scan.id);
        record.source_scan_digest = Some(scan_evidence_digest(&source_scan)?);
        source_scan_for_assessment = Some(source_scan);
        record
    } else {
        BuildRecord::planned(&recipe)
    };

    let artifact_scan = if let Some(artifact) = record
        .artifact
        .as_ref()
        .filter(|artifact| artifact.retained && matches!(record.status, BuildStatus::Succeeded))
    {
        let mut scan = scanner::scan_layer_artifact(&recipe, artifact, osv_mode).await?;
        if let Some(source_scan) = source_scan_for_assessment.as_ref() {
            scanner::apply_autonomous_vex_assessments(source_scan, &mut scan);
        }
        Some(scan)
    } else {
        None
    };
    if let Some(scan) = artifact_scan.as_ref() {
        record.artifact_scan_id = Some(scan.id);
        let external_vex = state.store.list_vex(recipe.id).await?;
        record.policy_decision = Some(gate::evaluate_gate(
            &recipe,
            Some(&record),
            Some(scan),
            &external_vex,
        ));
    }
    if let Some(scan) = artifact_scan.as_ref() {
        state.store.save_build_with_scan(&record, scan).await?;
    } else {
        state.store.save_build(&record).await?;
    }
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
    let excluded_roots = [state.store.data_dir().to_path_buf()];
    let scan =
        scanner::scan_recipe_excluding(&recipe, request, &state.work_dir, &excluded_roots).await?;
    state.store.save_scan(&scan).await?;
    Ok((StatusCode::CREATED, Json(scan)))
}

async fn get_gate(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> AppResult<Json<GateDecision>> {
    let recipe = load_recipe(&state, id).await?;
    Ok(Json(metadata_gate(&state, &recipe).await?))
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
    match input.status {
        crate::models::VexStatus::Fixed => {
            return Err(AppError::bad_request(
                "external fixed VEX is not accepted; Fulcr derives fixed status from exact artifact version and OSV evidence",
            ));
        }
        crate::models::VexStatus::NotAffected => {
            if !recipe.policy.allow_external_vex_overrides {
                return Err(AppError::bad_request(
                    "external not_affected VEX overrides are disabled by recipe policy",
                ));
            }
            if input.component.as_deref().is_none_or(str::is_empty)
                || input.justification.as_deref().is_none_or(str::is_empty)
                || input.detail.as_deref().is_none_or(str::is_empty)
                || input.author.as_deref().is_none_or(str::is_empty)
                || input.product.as_deref().is_none_or(str::is_empty)
                || input.expires_at.as_deref().is_none_or(str::is_empty)
            {
                return Err(AppError::bad_request(
                    "external not_affected VEX requires exact artifact product, component, justification, detail, author, and expires_at",
                ));
            }
            let expires_at = input.expires_at.as_deref().unwrap_or_default();
            match artifact_is_expired(expires_at) {
                Ok(false) => {}
                Ok(true) => {
                    return Err(AppError::bad_request(
                        "external not_affected VEX expires_at must be in the future",
                    ));
                }
                Err(error) => {
                    return Err(AppError::bad_request(format!(
                        "external not_affected VEX has invalid expires_at: {error}"
                    )));
                }
            }
            let builds = state.store.list_builds(id).await?;
            let expected_product = latest_build_evidence(&builds)
                .and_then(|build| build.artifact.as_ref())
                .map(|artifact| format!("urn:oci:blob:{}", artifact.digest))
                .ok_or_else(|| {
                    AppError::bad_request(
                        "external not_affected VEX requires a current retained artifact",
                    )
                })?;
            if input.product.as_deref() != Some(expected_product.as_str()) {
                return Err(AppError::bad_request(format!(
                    "external not_affected VEX product must equal {expected_product}"
                )));
            }
        }
        crate::models::VexStatus::Affected | crate::models::VexStatus::UnderInvestigation => {}
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
    let recipe = load_recipe(&state, id).await?;
    let builds = state.store.list_builds(id).await?;
    let decision_scan = load_decision_scan(&state, id, latest_build_evidence(&builds)).await?;
    let external = state.store.list_vex(id).await?;
    Ok(Json(combined_vex_statements(
        &recipe,
        decision_scan.as_ref(),
        &external,
    )))
}

async fn get_openvex(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    let recipe = load_recipe(&state, id).await?;
    let builds = state.store.list_builds(id).await?;
    let decision_scan = load_decision_scan(&state, id, latest_build_evidence(&builds)).await?;
    let external = state.store.list_vex(id).await?;
    let statements = combined_vex_statements(&recipe, decision_scan.as_ref(), &external);
    Ok(Json(openvex_document(&recipe, &statements)))
}

async fn get_attestation(
    Path(id): Path<Uuid>,
    State(state): State<AppState>,
) -> AppResult<Json<serde_json::Value>> {
    let recipe = load_recipe(&state, id).await?;
    let builds = state.store.list_builds(id).await?;
    let decision_scan = load_decision_scan(&state, id, latest_build_evidence(&builds)).await?;
    let external = state.store.list_vex(id).await?;
    let vex = combined_vex_statements(&recipe, decision_scan.as_ref(), &external);
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
    let decision_scan = load_decision_scan(&state, id, latest_build_evidence(&builds)).await?;
    let vex = state.store.list_vex(id).await?;
    Ok(Json(
        verified_slsa_provenance_document(&state, &recipe, &builds, decision_scan.as_ref(), &vex)
            .await?,
    ))
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
            HeaderValue::from_static("application/vnd.oci.image.manifest.v1+json"),
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
    if digest == digest_bytes(OCI_EMPTY_CONFIG_BYTES) {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(OCI_EMPTY_CONFIG_MEDIA_TYPE),
        );
        headers.insert(
            header::CONTENT_LENGTH,
            HeaderValue::from(OCI_EMPTY_CONFIG_BYTES.len()),
        );
        headers.insert("Docker-Content-Digest", header_value(&digest)?);
        return if include_body {
            Ok((headers, OCI_EMPTY_CONFIG_BYTES).into_response())
        } else {
            Ok((StatusCode::OK, headers).into_response())
        };
    }

    if let Some(recipe_id) = state.store.lookup_blob_recipe(&digest).await
        && let Some(recipe) = state.store.get_recipe(recipe_id).await?
    {
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
                let size = validate_cached_layer_metadata(&state, path, &layer.digest, layer.size)
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

        match metadata_document_by_digest(&state, &recipe, &digest).await {
            Ok(Some(document)) => {
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
            Ok(None) => {}
            Err(error) => {
                tracing::error!(
                    ?error,
                    recipe_id = %recipe.id,
                    %digest,
                    "skipping unreadable recipe evidence during metadata blob discovery"
                );
            }
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
    let decision_scan =
        load_decision_scan(state, recipe.id, latest_build_evidence(&builds)).await?;
    let external_vex = state.store.list_vex(recipe.id).await?;
    let vex = combined_vex_statements(recipe, decision_scan.as_ref(), &external_vex);
    let sbom = decision_scan
        .as_ref()
        .map(|scan| scan.sbom.clone())
        .unwrap_or_else(|| sbom_document(recipe));
    let sbom_artifact_type = if sbom.get("spdxVersion").is_some() {
        "application/spdx+json"
    } else {
        "application/vnd.cyclonedx+json"
    };
    let cbom = decision_scan
        .as_ref()
        .map(|scan| scan.cbom.clone())
        .unwrap_or_else(|| cbom_document(recipe));
    let slsa = verified_slsa_provenance_document(
        state,
        recipe,
        &builds,
        decision_scan.as_ref(),
        &external_vex,
    )
    .await?;

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
            slsa,
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
        let empty_config_digest = digest_bytes(OCI_EMPTY_CONFIG_BYTES);
        let manifest = json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "artifactType": artifact_type,
            "config": {
                "mediaType": OCI_EMPTY_CONFIG_MEDIA_TYPE,
                "digest": empty_config_digest,
                "size": OCI_EMPTY_CONFIG_BYTES.len()
            },
            "layers": [{
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
    let manifest = match materialized_image_manifest(state, recipe).await {
        Ok(manifest) => manifest,
        Err(AppError::Forbidden(_) | AppError::NotFound(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    Ok(
        metadata_documents(state, recipe, &MetadataSubject::image(&manifest))
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
        if let Ok(manifest) = materialized_image_manifest(state, &recipe).await {
            match metadata_documents(state, &recipe, &MetadataSubject::image(&manifest)).await {
                Ok(documents) => {
                    if let Some(document) = documents
                        .into_iter()
                        .find(|document| document.manifest_digest == digest)
                    {
                        return Ok(Some(document));
                    }
                }
                Err(error) => {
                    tracing::error!(
                        ?error,
                        recipe_id = %recipe.id,
                        %digest,
                        "skipping unreadable recipe evidence during metadata manifest discovery"
                    );
                }
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
    if let Some(expires_at) = artifact.expires_at.as_deref() {
        match artifact_is_expired(expires_at) {
            Ok(true) => {
                return Err(AppError::forbidden(format!(
                    "metadata gate allowed pull, but latest build {} artifact expired at {expires_at}",
                    build.id
                )));
            }
            Ok(false) => {}
            Err(error) => {
                return Err(AppError::forbidden(format!(
                    "metadata gate allowed pull, but latest build {} has invalid artifact expiry metadata: {error}",
                    build.id
                )));
            }
        }
    }
    let Some(path) = artifact.path.as_ref() else {
        return Err(AppError::forbidden(format!(
            "metadata gate allowed pull, but latest build {} artifact has no cache path",
            build.id
        )));
    };
    if let Err(error) =
        validate_existing_cached_layer(state, path, &artifact.digest, artifact.size).await
    {
        return Err(AppError::forbidden(format!(
            "metadata gate allowed pull, but cached artifact for build {} is invalid: {error}",
            build.id
        )));
    }
    Ok(artifact)
}

fn artifact_is_expired(expires_at: &str) -> anyhow::Result<bool> {
    let expires_at =
        time::OffsetDateTime::parse(expires_at, &time::format_description::well_known::Rfc3339)
            .context("parsing artifact expiry timestamp")?;
    Ok(expires_at <= time::OffsetDateTime::now_utc())
}

async fn load_recipe(state: &AppState, id: Uuid) -> AppResult<Recipe> {
    state
        .store
        .get_recipe(id)
        .await?
        .ok_or_else(|| AppError::not_found(format!("recipe {id} not found")))
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
    let vex = state.store.list_vex(recipe.id).await?;
    let latest_build = latest_build_evidence(&builds);
    let decision_scan = load_decision_scan(state, recipe.id, latest_build).await?;
    let mut decision = gate::evaluate_gate(recipe, latest_build, decision_scan.as_ref(), &vex);
    if let Some(build) = latest_build
        && let Some(reason) = source_scan_binding_error(state, recipe, build).await
    {
        decision.reasons.push(reason);
        decision.outcome = GateOutcome::Denied;
    }
    Ok(decision)
}

async fn load_decision_scan(
    state: &AppState,
    recipe_id: Uuid,
    latest_build: Option<&BuildRecord>,
) -> AppResult<Option<ScanReport>> {
    if let Some(scan_id) = latest_build.and_then(|build| build.artifact_scan_id) {
        return state
            .store
            .get_scan(recipe_id, scan_id)
            .await?
            .map(Some)
            .ok_or_else(|| {
                AppError::forbidden(format!(
                    "artifact assessment scan binding {scan_id} is missing"
                ))
            });
    }
    state.store.latest_scan(recipe_id).await.map_err(Into::into)
}

async fn source_scan_binding_error(
    state: &AppState,
    recipe: &Recipe,
    build: &BuildRecord,
) -> Option<String> {
    let (Some(source_scan_id), Some(expected_digest)) =
        (build.source_scan_id, build.source_scan_digest.as_deref())
    else {
        return None;
    };
    match state.store.get_scan(recipe.id, source_scan_id).await {
        Ok(Some(scan)) => {
            if scan.recipe_id != recipe.id
                || scan.recipe_digest != recipe.digest
                || !matches!(scan.mode, crate::models::ScanMode::Source)
                || !scan
                    .filesystem_digest
                    .as_deref()
                    .is_some_and(valid_sha256_digest)
            {
                return Some(format!(
                    "source scan binding {} has the wrong recipe identity or mode",
                    source_scan_id
                ));
            }
            match scan_evidence_digest(&scan) {
                Ok(actual_digest) if actual_digest == expected_digest => None,
                Ok(actual_digest) => Some(format!(
                    "source scan binding {} digest mismatch: expected {}, found {}",
                    source_scan_id, expected_digest, actual_digest
                )),
                Err(error) => Some(format!(
                    "source scan binding {} could not be digested: {}",
                    source_scan_id, error
                )),
            }
        }
        Ok(None) => Some(format!("source scan binding {} is missing", source_scan_id)),
        Err(error) => {
            tracing::error!(
                ?error,
                %source_scan_id,
                recipe_id = %recipe.id,
                "failed to load source scan binding"
            );
            Some(format!(
                "source scan binding {} is unreadable",
                source_scan_id
            ))
        }
    }
}

fn valid_sha256_digest(digest: &str) -> bool {
    digest.strip_prefix("sha256:").is_some_and(|value| {
        value.len() == 64 && value.chars().all(|character| character.is_ascii_hexdigit())
    })
}

async fn verified_slsa_provenance_document(
    state: &AppState,
    recipe: &Recipe,
    builds: &[BuildRecord],
    latest_scan: Option<&ScanReport>,
    external_vex: &[VexStatement],
) -> AppResult<serde_json::Value> {
    let latest_build = latest_build_evidence(builds);
    let vex = combined_vex_statements(recipe, latest_scan, external_vex);
    let mut document = slsa_provenance_document(recipe, latest_build, latest_scan, &vex)?;
    if let Some(build) = latest_build
        && let Some(reason) = source_scan_binding_error(state, recipe, build).await
    {
        if let Some(outcome) =
            document.pointer_mut("/predicate/runDetails/metadata/fulcrSlsaPolicy/outcome")
        {
            *outcome = json!("denied");
        }
        if let Some(findings) = document
            .pointer_mut("/predicate/runDetails/metadata/fulcrSlsaPolicy/findings")
            .and_then(serde_json::Value::as_array_mut)
        {
            findings.push(json!({
                "severity": "high",
                "category": "slsa-invalid-source-scan-binding",
                "message": reason,
                "evidence": format!("build.{}", build.id)
            }));
        }
    }
    Ok(document)
}

fn latest_build_evidence(builds: &[BuildRecord]) -> Option<&BuildRecord> {
    builds
        .iter()
        .rev()
        .find(|build| !matches!(build.status, BuildStatus::Planned))
}

async fn execute_build(
    state: &AppState,
    recipe: &Recipe,
    request: BuildRequest,
) -> AppResult<BuildRecord> {
    let started_at = timestamp();
    let working_dir = resolve_working_dir(recipe, &state.work_dir)?;
    let mut notes = vec![
        "fulcr did not execute recipe commands; this record imports a prebuilt OCI layer artifact"
            .to_string(),
    ];
    if !request.environment.is_empty() {
        notes.push(
            "build request environment was ignored because native execution is disabled"
                .to_string(),
        );
    }
    let mut status = BuildStatus::Succeeded;

    let artifact = read_artifact_ref(
        state,
        recipe,
        &request,
        &working_dir,
        &mut status,
        &mut notes,
    )
    .await?;
    if artifact.is_none() {
        status = BuildStatus::Failed;
    }

    let record = BuildRecord {
        id: Uuid::new_v4(),
        recipe_id: recipe.id,
        recipe_digest: recipe.digest.clone(),
        source_scan_id: None,
        source_scan_digest: None,
        artifact_scan_id: None,
        policy_decision: None,
        status,
        created_at: started_at.clone(),
        started_at: Some(started_at),
        finished_at: Some(timestamp()),
        command: Vec::new(),
        working_dir: Some(working_dir),
        exit_code: None,
        artifact,
        stdout_tail: None,
        stderr_tail: None,
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

    let retained = request.cache_artifact || recipe.policy.retain_artifact;
    let (validated_path, temporary_path) = if retained {
        let temporary_path = state
            .store
            .cache_dir()
            .join(format!(".ingest-{}", Uuid::new_v4()));
        fs::copy(&canonical, &temporary_path).await?;
        (temporary_path.clone(), Some(temporary_path))
    } else {
        (canonical.clone(), None)
    };

    let size = match layer_artifact_size(&validated_path).await {
        Ok(size) => size,
        Err(error) => {
            if let Some(path) = temporary_path.as_ref() {
                let _ = fs::remove_file(path).await;
            }
            *status = BuildStatus::Failed;
            notes.push(format!(
                "declared artifact is too large or unreadable: {error}"
            ));
            return Ok(None);
        }
    };
    if let Err(error) = validate_oci_layer_tar_file(&validated_path, size).await {
        if let Some(path) = temporary_path.as_ref() {
            let _ = fs::remove_file(path).await;
        }
        *status = BuildStatus::Failed;
        notes.push(format!(
            "declared artifact is not a valid uncompressed OCI layer tar: {error}"
        ));
        return Ok(None);
    }

    let digest = digest_file(&validated_path).await?;
    let (path, expires_at) = if let Some(temporary_path) = temporary_path {
        let cache_path = state.store.cache_dir().join(cache_file_name(&digest));
        set_cache_file_read_only(&temporary_path).await?;
        match fs::hard_link(&temporary_path, &cache_path).await {
            Ok(()) => {
                fs::remove_file(&temporary_path).await?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                fs::remove_file(&temporary_path).await?;
                validate_existing_cached_layer(state, &cache_path, &digest, size).await?;
            }
            Err(error) => {
                let _ = fs::remove_file(&temporary_path).await;
                return Err(error.into());
            }
        }
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

async fn validate_cached_layer_metadata(
    state: &AppState,
    path: &FsPath,
    expected_digest: &str,
    expected_size: u64,
) -> anyhow::Result<u64> {
    let expected_path = state
        .store
        .cache_dir()
        .join(cache_file_name(expected_digest));
    if path != expected_path {
        anyhow::bail!(
            "layer cache path does not match content digest: expected {}, found {}",
            expected_path.display(),
            path.display()
        );
    }
    let metadata = fs::symlink_metadata(path)
        .await
        .with_context(|| format!("reading cache metadata for {}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        anyhow::bail!("layer cache path is not a regular file");
    }
    if metadata.len() != expected_size {
        anyhow::bail!(
            "layer artifact size changed: expected {expected_size}, found {}",
            metadata.len()
        );
    }
    Ok(metadata.len())
}

async fn validate_existing_cached_layer(
    state: &AppState,
    path: &FsPath,
    expected_digest: &str,
    expected_size: u64,
) -> anyhow::Result<()> {
    validate_cached_layer_metadata(state, path, expected_digest, expected_size).await?;
    let actual_digest = digest_file(path).await?;
    if actual_digest != expected_digest {
        anyhow::bail!(
            "existing cache blob digest mismatch: expected {expected_digest}, found {actual_digest}"
        );
    }
    validate_oci_layer_tar_file(path, expected_size).await?;
    Ok(())
}

async fn set_cache_file_read_only(path: &FsPath) -> anyhow::Result<()> {
    let mut permissions = fs::metadata(path).await?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).await?;
    Ok(())
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

type AppResult<T> = Result<T, AppError>;

#[derive(Debug)]
enum AppError {
    BadRequest(String),
    Forbidden(String),
    NotFound(String),
    Oci {
        status: StatusCode,
        code: &'static str,
        message: String,
    },
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

    fn into_oci(self, not_found_code: &'static str) -> Self {
        match self {
            Self::BadRequest(message) => Self::Oci {
                status: StatusCode::BAD_REQUEST,
                code: "NAME_INVALID",
                message,
            },
            Self::Forbidden(message) => Self::Oci {
                status: StatusCode::FORBIDDEN,
                code: "DENIED",
                message,
            },
            Self::NotFound(message) => Self::Oci {
                status: StatusCode::NOT_FOUND,
                code: not_found_code,
                message,
            },
            Self::Internal(error) => {
                tracing::error!(?error, "internal OCI error");
                Self::Oci {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    code: "UNKNOWN",
                    message: "internal server error".to_string(),
                }
            }
            error @ Self::Oci { .. } => error,
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::BadRequest(message) => (StatusCode::BAD_REQUEST, message),
            Self::Forbidden(message) => (StatusCode::FORBIDDEN, message),
            Self::NotFound(message) => (StatusCode::NOT_FOUND, message),
            Self::Oci {
                status,
                code,
                message,
            } => {
                return (
                    status,
                    Json(json!({ "errors": [{ "code": code, "message": message }] })),
                )
                    .into_response();
            }
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
