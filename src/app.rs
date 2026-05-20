use std::path::{Component, PathBuf};
use std::sync::Arc;

use axum::{
    extract::{Path, Request, State},
    http::{header, HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde_json::json;
use tokio::fs;
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
        timestamp, timestamp_after_seconds, ArtifactRef, BuildRecord, BuildRequest, BuildStatus,
        GateDecision, GateOutcome, Recipe, RecipeInput, ScanReport, ScanRequest, VexInput,
        VexStatement,
    },
    scanner,
    store::Store,
};

#[derive(Clone)]
pub struct AppState {
    store: Store,
    work_dir: PathBuf,
    auth_token: Option<Arc<String>>,
}

pub fn router(store: Store, work_dir: PathBuf) -> Router {
    router_with_auth(store, work_dir, std::env::var("fulcr_TOKEN").ok())
}

pub fn router_with_auth(store: Store, work_dir: PathBuf, auth_token: Option<String>) -> Router {
    if auth_token.is_none() {
        tracing::warn!(
            "fulcr_TOKEN is not set; mutating endpoints are unauthenticated. \
             Bind to 127.0.0.1 only or set fulcr_TOKEN before exposing this listener."
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
            "/v2/:name/manifests/:reference",
            get(oci_manifest).head(oci_manifest_head),
        )
        .route(
            "/v2/:namespace/:name/manifests/:reference",
            get(oci_manifest).head(oci_manifest_head),
        )
        .route(
            "/v2/:name/blobs/:digest",
            get(oci_blob).head(oci_blob_head),
        )
        .route(
            "/v2/:namespace/:name/blobs/:digest",
            get(oci_blob).head(oci_blob_head),
        )
        .route(
            "/v2/:name/referrers/:digest",
            get(oci_referrers_stub),
        )
        .route(
            "/v2/:namespace/:name/referrers/:digest",
            get(oci_referrers_stub),
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

async fn require_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method();
    let path = request.uri().path();

    // Read-only and health endpoints remain open; mutating endpoints require the token when set.
    let needs_auth = matches!(method, &Method::POST | &Method::PUT | &Method::PATCH | &Method::DELETE)
        || path.starts_with("/v1/recipes") && path.ends_with("/vex") && method == Method::POST;

    if !needs_auth {
        return next.run(request).await;
    }

    let Some(expected) = state.auth_token.as_ref() else {
        return next.run(request).await;
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
        _ => (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "missing or invalid bearer token" })),
        )
            .into_response(),
    }
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

async fn oci_referrers_stub() -> Response {
    use oci_spec::image::{ImageIndexBuilder, MediaType};

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.oci.image.index.v1+json"),
    );

    let index = ImageIndexBuilder::default()
        .schema_version(2u32)
        .media_type(MediaType::ImageIndex)
        .manifests(vec![])
        .build()
        .unwrap();

    (headers, Json(index)).into_response()
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
        builds.last(),
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
    Ok(Json(attestation_document(&recipe, builds.last(), &vex)?))
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
        builds.last(),
        latest_scan.as_ref(),
        &vex,
    )?))
}

async fn oci_manifest(
    Path(params): Path<std::collections::HashMap<String, String>>,
    State(state): State<AppState>,
) -> AppResult<Response> {
    oci_manifest_response(params, state, true).await
}

async fn oci_manifest_head(
    Path(params): Path<std::collections::HashMap<String, String>>,
    State(state): State<AppState>,
) -> AppResult<Response> {
    oci_manifest_response(params, state, false).await
}

async fn oci_manifest_response(
    params: std::collections::HashMap<String, String>,
    state: AppState,
    include_body: bool,
) -> AppResult<Response> {
    let name = params.get("name").cloned().unwrap_or_default();
    let namespace = params.get("namespace").cloned();
    let full_name = if let Some(ns) = namespace {
        format!("{ns}/{name}")
    } else {
        name.clone()
    };
    let reference = params.get("reference").cloned().unwrap_or_default();

    let recipe = if let Ok(id) = Uuid::parse_str(&reference) {
        state.store.get_recipe(id).await?.filter(|r| r.name == name || r.name == full_name)
    } else {
        if let Some(r) = state.store.lookup_recipe(&name, &reference).await? {
            Some(r)
        } else {
            state.store.lookup_recipe(&full_name, &reference).await?
        }
    };

    let recipe = recipe.ok_or_else(|| AppError::not_found(format!("manifest {full_name}:{reference} not found")))?;

    enforce_manifest_gate(&state, &recipe).await?;

    let config = serde_json::to_vec(&recipe)?;
    let config_digest = crate::digest::digest_bytes(&config);
    
    use oci_spec::image::{ImageManifestBuilder, MediaType, DescriptorBuilder};

    let annotations = std::collections::HashMap::from([
        ("org.opencontainers.image.source".to_string(), recipe.source.repo.clone()),
        ("org.opencontainers.image.revision".to_string(), recipe.source.revision.clone()),
        ("dev.fulcr.materialized".to_string(), "false".to_string()),
        ("dev.fulcr.retention".to_string(), if recipe.policy.retain_artifact { "selective".to_string() } else { "ephemeral".to_string() }),
        ("dev.fulcr.note".to_string(), "metadata-only manifest; artifact is constructed ad hoc".to_string()),
    ]);

    let config_desc = DescriptorBuilder::default()
        .media_type(MediaType::Other("application/vnd.fulcr.recipe.config.v1+json".to_string()))
        .digest(config_digest.clone().parse::<oci_spec::image::Digest>().unwrap())
        .size(config.len() as u64)
        .build()
        .unwrap();

    let manifest = ImageManifestBuilder::default()
        .schema_version(2u32)
        .media_type(MediaType::ImageManifest)
        .config(config_desc)
        .layers(vec![])
        .annotations(annotations)
        .build()
        .unwrap();

    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_digest = crate::digest::digest_bytes(&manifest_bytes);

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/vnd.oci.image.manifest.v1+json"),
    );
    headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from(manifest_bytes.len()),
    );
    headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&manifest_digest).unwrap(),
    );

    if include_body {
        Ok((headers, manifest_bytes).into_response())
    } else {
        Ok((StatusCode::OK, headers).into_response())
    }
}

async fn oci_blob(
    Path(params): Path<std::collections::HashMap<String, String>>,
    State(state): State<AppState>,
) -> AppResult<Response> {
    oci_blob_response(params, state, true).await
}

async fn oci_blob_head(
    Path(params): Path<std::collections::HashMap<String, String>>,
    State(state): State<AppState>,
) -> AppResult<Response> {
    oci_blob_response(params, state, false).await
}

async fn oci_blob_response(
    params: std::collections::HashMap<String, String>,
    state: AppState,
    include_body: bool,
) -> AppResult<Response> {
    let digest = params.get("digest").cloned().unwrap_or_default();

    if let Some(recipe_id) = state.store.lookup_blob_recipe(&digest).await {
        if let Some(recipe) = state.store.get_recipe(recipe_id).await? {
            let config = serde_json::to_vec(&recipe)?;
            // Re-verify the digest to defend against index drift.
            if crate::digest::digest_bytes(&config) == digest {
                let mut headers = HeaderMap::new();
                headers.insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/vnd.fulcr.recipe.config.v1+json"),
                );
                headers.insert(header::CONTENT_LENGTH, HeaderValue::from(config.len()));
                headers.insert(
                    "Docker-Content-Digest",
                    HeaderValue::from_str(&digest).unwrap(),
                );
                return if include_body {
                    Ok((headers, config).into_response())
                } else {
                    Ok((StatusCode::OK, headers).into_response())
                };
            }
        }
    }

    let cache_path = state.store.cache_dir().join(crate::digest::cache_file_name(&digest));
    if let Ok(bytes) = fs::read(&cache_path).await {
        if crate::digest::digest_bytes(&bytes) != digest {
            // Defense in depth: refuse to serve a cached blob whose digest no longer matches.
            return Err(AppError::not_found(format!("blob {digest} not found")));
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        headers.insert(header::CONTENT_LENGTH, HeaderValue::from(bytes.len()));
        headers.insert(
            "Docker-Content-Digest",
            HeaderValue::from_str(&digest).unwrap(),
        );
        return if include_body {
            Ok((headers, bytes).into_response())
        } else {
            Ok((StatusCode::OK, headers).into_response())
        };
    }

    Err(AppError::not_found(format!("blob {digest} not found")))
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
        builds.last(),
        latest_scan.as_ref(),
        &vex,
    ))
}

async fn execute_native(
    cmd: Vec<String>,
    env: Vec<String>,
    working_dir: &str,
    _network_disabled: bool,
    monitor_security: bool,
) -> anyhow::Result<(i64, Vec<u8>, Vec<u8>, Vec<String>)> {
    if cmd.is_empty() {
        return Err(anyhow::anyhow!("empty command"));
    }

    // In a real pure-Rust OCI context, you would `unshare` and configure namespaces here
    // before executing to emulate network disabling and drop capabilities. 
    // Since we are mocking the execution flow locally without Docker:
    // (A full local sandbox would require Linux-specific `chroot` or user namespace logic)
    
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

    let child = command.spawn().map_err(|e| anyhow::anyhow!("failed to spawn: {}", e))?;
    
    let result = child.wait_with_output().await.map_err(|e| anyhow::anyhow!("failed to wait: {}", e))?;

    let exit_code = result.status.code().unwrap_or(1) as i64;
    let stdout_buf = result.stdout;
    let stderr_buf = result.stderr;
    let mut anomalies = Vec::new();

    // Security monitoring on output
    if monitor_security {
        let out_str = String::from_utf8_lossy(&stdout_buf);
        let err_str = String::from_utf8_lossy(&stderr_buf);
        for s in out_str.lines().chain(err_str.lines()) {
            if s.contains("curl ") || s.contains("wget ") || s.contains("chmod ") || s.contains("nc ") {
                let warn = format!("[SECURITY WARN] Suspicious runtime activity detected: {}", s);
                println!("{}", warn);
                anomalies.push(s.trim().to_string());
            }
        }
    }

    Ok((exit_code, stdout_buf, stderr_buf, anomalies))
}

async fn execute_build(
    state: &AppState,
    recipe: &Recipe,
    request: BuildRequest,
) -> AppResult<BuildRecord> {
    if recipe.build.command.is_empty() {
        return Err(AppError::bad_request("recipe build command is empty"));
    }

    let started_at = timestamp();
    let working_dir = resolve_working_dir(recipe, &state.work_dir)?;
    
    let env: Vec<String> = request.environment.iter().map(|(k, v)| format!("{}={}", k, v)).collect();

    // 1. Build Phase (network allowed)
    let (build_exit, mut stdout_buf, mut stderr_buf, mut all_anomalies) = execute_native(
        recipe.build.command.clone(),
        env.clone(),
        &working_dir.to_string_lossy(),
        false, // network_disabled = false
        false, // monitor_security = false
    ).await.unwrap_or((1, Vec::new(), Vec::new(), Vec::new()));

    let mut exit_code = Some(build_exit);

    // 2. Run / Scan Phase (network mocked to disabled, monitor for C2)
    if build_exit == 0 {
        if let Some(run_cmd) = &recipe.build.run_command {
            let (run_exit, run_stdout, run_stderr, run_anomalies) = execute_native(
                run_cmd.clone(),
                env,
                &working_dir.to_string_lossy(),
                true,  // network_disabled = true
                true,  // monitor_security = true
            ).await.unwrap_or((1, Vec::new(), Vec::new(), Vec::new()));
            exit_code = Some(run_exit);
            stdout_buf.extend_from_slice(b"
--- RUN PHASE ---
");
            stdout_buf.extend_from_slice(&run_stdout);
            stderr_buf.extend_from_slice(b"
--- RUN PHASE ---
");
            stderr_buf.extend_from_slice(&run_stderr);
            all_anomalies.extend(run_anomalies);
        }
    }

    let mut status = if exit_code.unwrap_or(1) == 0 {
        BuildStatus::Succeeded
    } else {
        BuildStatus::Failed
    };

    let mut notes = Vec::new();
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
        || artifact
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::RootDir | Component::Prefix(_)))
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

    let bytes = fs::read(&canonical).await?;

    let digest = digest_bytes(&bytes);
    let retained = request.cache_artifact || recipe.policy.retain_artifact;
    let (path, expires_at) = if retained {
        let cache_path = state.store.cache_dir().join(cache_file_name(&digest));
        fs::write(&cache_path, &bytes).await?;
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
        digest,
        size: bytes.len() as u64,
        retained,
        path,
        expires_at,
    }))
}

fn resolve_working_dir(recipe: &Recipe, work_dir: &std::path::Path) -> anyhow::Result<PathBuf> {
    let mut dir = recipe
        .source
        .path
        .clone()
        .unwrap_or_else(|| work_dir.to_path_buf());
    if let Some(path) = &recipe.build.working_dir {
        dir.push(path);
    }
    let canon = std::fs::canonicalize(&dir)?;
    if !canon.starts_with(work_dir) {
        anyhow::bail!("working directory escapes the configured work dir");
    }
    Ok(canon)
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
