# fulcr

`fulcr` is a metadata-first virtual OCI registry for containerized developer environments such as DevContainers. It treats source, locked inputs, builder identity, SBOM, CBOM, VEX, SLSA provenance, scans, attestations, and policy decisions as the durable artifact. Image bytes are derived materializations: they may be built explicitly, cached temporarily, served through normal OCI read paths, or denied by policy, but they are not the registry's source of truth.

The value proposition is both security and storage: unsafe images are never materialized into developer workstations, CI runners, or runtimes, and rarely reused image layers do not accumulate as permanent registry state. Conventional registries keep the pile of image blobs first and attach proof later; `fulcr` keeps the proof first and creates the pile only when policy allows it.

Source, locked inputs, builder identity, policy, SBOM, CBOM, VEX, SLSA provenance, scans, and attestations are the durable truth. Pushed image bytes, rebuilt layers, compiled binaries, and build intermediates are temporary evidence unless an explicit retention policy says otherwise. The prototype currently serves pullable image content only when a recipe build has produced and retained an uncompressed OCI layer tar.

## Virtual Image Model

`fulcr` turns an image reference into a policy-gated projection of source and metadata. Materialization is a derived state, not the primary registry record:

```text
Git/source + recipe + metadata
     |
     v
fulcr metadata gate
     |
   allow? deny?
  |      |
  v      v
serve approved materialization     no build, no stream
  |
  v
stream manifest/config/layers
  |
  v
discard, retain, or short-cache bytes by policy
```

From the OCI client's perspective, successful reads still use normal manifests, descriptors, digests, blobs, and referrers. Internally, the image is a source-bound metadata record until an explicit or pre-existing materialization supplies descriptors and bytes that `fulcr` can serve without violating OCI client expectations. Pull-time build may be a future optimization for fast, deterministic cases, but it is not the core contract.

Release tags and digest references SHOULD resolve to stable recipe or materialization identity. Floating development references MAY point at changing source revisions, but they still become pullable only after metadata is accepted and any required materialization exists.

## The DevContainer Protection Model

`fulcr` achieves its maximum security value when paired with containerized developer environments like **DevContainers**. 

When developers use raw native environments (running `npm install` or `cargo build` directly on macOS or Windows), they bypass OCI registries entirely, leaving themselves vulnerable to malicious package lifecycle scripts or supply-chain worms. 

By mandating a DevContainer workflow, the entire developer experience is forced through the OCI protocol boundary. When VS Code or another IDE attempts to start the DevContainer, the local container engine (e.g., Docker) routes the pull or build request through `fulcr`. Before the DevContainer is allowed to start, `fulcr` scans the repository's locking files, dependencies, and configuration. If it detects missing lockfile integrity, untrusted dependency sources, or suspicious pre-install scripts, `fulcr` firmly denies the OCI materialization.

The malicious payload is never executed because `fulcr` refuses to hand over the container environment to the developer's machine in the first place, establishing a true zero-trust perimeter at zero added cost to the developer's daily routine.

## OCI Contract

`fulcr` MUST implement the latest published OCI specifications used by container registries and images. The current target is OCI Distribution Specification v1.1.1 and OCI Image Specification v1.1.1.

The registry MUST expose standard OCI Distribution API behavior for OCI clients, including `/v2/`, manifest access, content descriptors, media types, digest-addressed blobs, and OCI artifact references where metadata documents are attached. It MUST NOT require proprietary client behavior for image pull, manifest resolution, or artifact discovery.

Binary content MUST be disposable. During future push or image intake, `fulcr` MAY temporarily hold image layers, config blobs, compiled binaries, and archives long enough to scan them and create metadata. During explicit materialization, `fulcr` MAY cache build outputs long enough to satisfy normal OCI reads. In both cases, it MUST NOT preserve image layers, config blobs, compiled binaries, image archives, or build outputs as durable registry state unless an explicit retention policy allows it.

## Metadata Engine

`fulcr` is a developer-protection metadata engine based on SBOM, CBOM, VEX, SLSA provenance, and scan evidence:

- SBOM answers what software components are expected in the image.
- CBOM answers what cryptographic material, algorithms, protocols, and crypto-relevant configuration are expected.
- VEX answers whether known vulnerabilities are exploitable, fixed, not affected, or under investigation for this recipe and source revision.
- SLSA provenance records the source, builder, materials, parameters, byproducts, and build/run details in a standard in-toto statement shape.
- Scan reports capture source, filesystem, image, and binary evidence used by the metadata gate.

The registry MUST store and process metadata as first-class OCI artifacts. It MUST use metadata and VEX risk to decide whether an image can be materialized or served. It MUST NOT use retained binary blobs as the source of truth, and it MUST deny materialization before risky content reaches developer environments.

## Native Scanner

`fulcr` includes a native Rust scanner module. The scanner does not shell out to external scanners. It scans the recipe source path, an explicitly supplied filesystem path, or an OCI/Docker image archive and produces:

- CycloneDX-style SBOM output from detected package manifests, lockfiles, and OS package databases
- CBOM-style crypto inventory from certificates, keys, crypto libraries, protocols, algorithms, and crypto-relevant config
- VEX candidates for findings that require exploitability triage
- scan findings for suspicious build scripts, ad-hoc binaries, crypto drift, and metadata misalignment

The scanner uses specialized Rust crates for the parts that should not be hand-parsed in normal operation: `ignore` for gitignore-aware traversal, `cargo-lock` for Cargo lockfiles, `toml` for Cargo manifests, `serde_json` for npm lockfiles and manifests, `serde_yaml_ng` for pnpm lockfiles, `roxmltree` for Maven POMs, `pem` and `x509-parser` for PEM and certificate material, `semver` for exact-version validation, `tar`, `flate2`, and `zstd` for image archives, `object` for binary metadata, and `sha2` for content digests.

The scan request supports three modes:

```json
{
  "mode": "source",
  "path": "/path/to/source-or-archive",
  "max_file_bytes": 1048576
}
```

| Mode | Behavior |
|---|---|
| `source` | Scans the recipe source path or `path` as source metadata |
| `filesystem` | Scans `path` as an already reconstructed root filesystem |
| `image_archive` | Accepts an uncompressed, gzip-compressed, or zstd-compressed Docker `docker save` archive or OCI image layout archive, unpacks layers in order, applies overlay whiteouts, reconstructs a temporary rootfs, scans it, and deletes the temporary bytes |

The current scanner detects:

- `Cargo.lock`, `Cargo.toml`, `package-lock.json`, `package.json`, `pnpm-lock.yaml`, `requirements.txt`, `go.mod`, `pom.xml`, `packages.lock.json`
- Debian `var/lib/dpkg/status` and Alpine `lib/apk/db/installed`
- PEM/certificate/key material and crypto strings such as TLS versions, OpenSSL, rustls, MD5, SHA-1, RC4, and 3DES
- suspicious command patterns such as remote shell execution, reverse-shell hints, and encoded command execution
- executable binary files that are not explained by source metadata

The scanner also turns SBOM and CBOM into gateable posture evidence. SBOM policy findings are emitted for unpinned dependency specs, missing lockfile integrity hashes, direct or local dependency sources that require provenance review, npm lifecycle scripts, and package scripts that reference tokens, registries, or publishing behavior. CBOM policy findings are emitted for private key material, legacy protocols, weak algorithms, weak key-size hints, SHA-1 or MD5 signature hints, and expired crypto library families such as OpenSSL 1.0.x or 1.1.1.

These controls intentionally sit beside VEX rather than replacing it. SBOM/CBOM findings answer whether the dependency and crypto posture is acceptable before a derived image is materialized; VEX answers whether a known vulnerability is exploitable in this image context.

To bridge the gap between abstract metadata and real-world exploitation, `fulcr` employs a hybrid VEX (Vulnerability Exploitability eXchange) model:

- **Implicit VEX (The Baseline):** Since `fulcr` natively generates exact Package URLs (PURLs) via its SBOM scanner, it can implicitly connect the dots by checking dependencies against structured OSV feeds (like OSV.dev or GitHub Advisories). Matches automatically generate a `VexCandidate` with an `under_investigation` or `affected` status in the scan report, providing out-of-the-box CVE protection without requiring external scanning tools.
- **Explicit VEX (The Override):** When an implicit OSV match flags a vulnerability, security teams and CI systems can supply explicit OpenVEX documents via the `/v1/recipes/:id/vex` endpoint to override the finding. Because these VEX statements are cryptographically anchored to the `fulcr` recipe digest, an override like `not_affected` cleanly unblocks the image pull while keeping a signed, verifiable record that applies *only* to that exact build context.

Binary deep scanning is part of every filesystem and image scan. Binary-looking files are inspected for ELF, Mach-O, and PE metadata where possible, including format, architecture, entrypoint, sections, imported or undefined symbols, inferred linked libraries, and security-relevant strings. The scanner uses this to identify linked crypto libraries, legacy crypto primitives, network-capable binaries, and ad-hoc executable files.

The scanner output is persisted as durable metadata. `/v1/recipes/:id/sbom` and `/v1/recipes/:id/cbom` return the latest scan-derived documents when a scan exists, otherwise they fall back to recipe-declared metadata.

## SLSA Provenance

`fulcr` emits SLSA provenance at `GET /v1/recipes/:id/slsa`. The document uses an in-toto statement envelope and SLSA v1 predicate type:

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "predicateType": "https://slsa.dev/provenance/v1"
}
```

The SLSA predicate records:

- source repository and revision
- recipe digest and build definition
- builder identity and optional builder digest
- declared material digests
- latest scan report digest when available
- SBOM, CBOM, and OpenVEX byproduct digests
- latest build invocation ID and timestamps when a build exists
- output artifact subject digest when a build produced an artifact

`fulcr` also evaluates a tightened SLSA posture policy. The policy requires an immutable source revision, a sha256-pinned builder, sha256-digested materials, latest scan evidence for the recipe digest, durable metadata-only retention, and build evidence that matches the recipe whenever a build record exists. The SLSA document exposes these checks under `predicate.runDetails.metadata.fulcrSlsaPolicy`, and the materialization gate denies by default when the policy is not satisfied.

SLSA is not the whole security model. In `fulcr`, SLSA is the interoperable provenance receipt and provenance completeness signal; SBOM and CBOM are inventories and posture controls; VEX is the exploitability assertion; scan reports are evidence; the metadata gate is the registry verdict.

## Metadata Gate

`fulcr` evaluates a metadata gate at `GET /v1/recipes/:id/gate`. The gate denies materialization when it sees:

- VEX `affected` or `under_investigation` statements for the recipe
- SBOM findings for unpinned dependencies, missing integrity, untrusted dependency sources, lifecycle scripts, or suspicious package scripts
- CBOM findings for private key material, crypto policy drift, weak primitives, weak key-size hints, or EOL crypto libraries
- SLSA findings for unpinned source revisions, missing builder digests, undigested materials, missing or stale scan evidence, stale or failed build evidence, incomplete build timestamps, or disabled durable metadata-only retention
- scan findings for ad-hoc binaries, suspicious build behavior, or metadata misalignment
- VEX candidates that still require triage

Build execution and OCI manifest resolution call the same gate. If the latest metadata is denied, `fulcr` refuses to build, materialize, or serve a manifest for that recipe.

## Future Sandbox Extension

Runtime sandboxing is intentionally not part of the current implementation. It can be added later as a platform-scoped evidence source, preferably through native or VM-backed workers that produce signed reports. Until then, `fulcr` relies on static source, image, binary, SBOM, CBOM, VEX, SLSA, and build metadata rather than pretending a local host sandbox can prove every target platform.

## Standard OCI Personas

`fulcr` uses standard OCI personas and use-cases:

| Persona | OCI Use-Case | `fulcr` Behavior |
|---|---|---|
| Developer | Pull, build, or inspect a dependency-backed image | Receives only images whose dependency, crypto, VEX, and provenance posture passed the metadata gate |
| CI runner | Build or test source-bound artifacts | Gets an allow/deny decision before build scripts can execute with CI credentials or package tokens nearby |
| Image producer | Register source metadata or future pushed-image evidence | Registers recipes today; future push intake can convert uploaded bytes into metadata |
| OCI registry | Serve manifests, descriptors, blobs, and referrers | Resolves metadata, applies the gate, and serves only approved available materializations |
| OCI client | Pull an image by tag or digest | Receives OCI-compliant manifests and byte streams only when descriptors and blobs are already available to serve |
| Runtime or orchestrator | Deploy an image | Pulls through standard OCI behavior and enforces digest identity |
| Security scanner | Discover SBOM, CBOM, VEX, SLSA, and attestations | Reads OCI artifacts and referrers attached to the recipe or image digest |
| Auditor | Trace deployed software to source and evidence | Reviews recipe, materials, metadata digests, SLSA provenance, VEX status, and build records |

## Future Push Intake Flow

Push intake is not implemented in the current prototype. When added, push remains an ingestion path for evidence rather than durable blob storage:

```text
OCI producer pushes image
  |
  v
fulcr temporarily accepts manifest/config/layers
  |
  v
fulcr creates or updates SBOM, CBOM, VEX risk metadata, SLSA provenance, scan evidence, and build evidence
  |
  v
fulcr stores metadata and policy state
  |
  v
fulcr deletes pushed binary bytes
```

Push is not durable storage. Push is an ingestion event that converts binary evidence into metadata.

## Pull Flow

```text
OCI client pulls name:tag or name@digest
        |
        v
fulcr resolves source-bound recipe and metadata
        |
        v
fulcr evaluates SBOM, CBOM, VEX, SLSA provenance, scans, policy, and attestations
        |
        v
if allowed and materialized content exists, fulcr prepares OCI descriptors
        |
        v
fulcr streams manifest/config/layers with compliant digests
        |
        v
fulcr keeps metadata durable and retains/caches bytes only by explicit policy
```

If VEX risk or policy denies the request, `fulcr` MUST NOT build, materialize, or stream image bytes and MUST return an OCI-compliant error response. If policy allows the request but no approved materialization exists, `fulcr` MUST fail closed rather than block the pull on an unbounded build. Operators can create materialization through the metadata API before retrying the OCI pull.

## VEX Risk Gate

VEX is the gate between preserved metadata and derived binary materialization.

| VEX Status | Default Build/Pull Decision | Rationale |
|---|---|---|
| `not_affected` | Allow | The vulnerable condition is not exploitable for this image context |
| `fixed` | Allow when the fixed component is present | The image context contains the remediation |
| `affected` | Deny unless an explicit exception policy allows it | The vulnerability is relevant to this image context |
| `under_investigation` | Deny by default for production | The registry cannot yet prove acceptable risk |
| missing VEX for required CVE | Deny by default for production | The registry lacks an accountable exploitability statement |

The policy engine MAY vary these defaults by environment, but it MUST record the decision as durable metadata. A denied pull MUST NOT trigger materialization.

## Gherkin Requirements

```gherkin
Feature: Developer registry that protects developer environments
  fulcr MUST protect developer workstations, CI runners, and runtimes by denying unsafe materialization while remaining compatible with standard OCI clients.

  Background:
    Given the latest supported OCI Distribution Specification is "v1.1.1"
    And the latest supported OCI Image Specification is "v1.1.1"
    And a source-bound recipe or pushed image intake exists for "hello-service:1.0.0"
    And the registry has SBOM, CBOM, VEX, SLSA, scan, and attestation metadata for the reference

  Scenario: Developer environment is protected before pull
    Given a developer workstation, CI runner, or runtime requests "hello-service:1.0.0"
    When the latest metadata contains denied SBOM, CBOM, VEX, SLSA, scan, or attestation evidence
    Then the registry MUST deny materialization before build scripts, package payloads, image layers, or generated binaries reach that environment
    And the registry MUST expose the denial reason as metadata evidence

  Scenario: OCI client probes the registry
    When an OCI client sends "GET /v2/"
    Then the registry MUST return an OCI-compliant success response
    And the registry MUST NOT require proprietary client extensions

  Scenario: OCI client resolves a manifest
    When an OCI client requests the manifest for "hello-service:1.0.0"
    Then the registry MUST return an OCI Image Specification v1.1.1 compliant manifest
    And the manifest MUST contain valid OCI media types, descriptors, sizes, and digests
    And the manifest SHOULD expose SBOM, CBOM, VEX, SLSA, and attestation metadata through OCI artifact references

  Scenario: Future OCI push intake converts bytes to metadata
    Given push intake support is enabled
    And an OCI producer has an image manifest, config blob, and layer blobs
    When the producer pushes the image to the registry
    Then the registry MUST accept the push through standard OCI Distribution behavior
    And the registry MUST treat the pushed binaries as temporary intake
    And the registry MUST scan or process the pushed bytes to create SBOM, CBOM, VEX risk metadata, SLSA provenance, and build evidence
    And the registry MUST preserve the generated metadata
    And the registry MUST preserve OCI manifest information as metadata
    And the registry MUST delete config blobs, layer blobs, image archives, and compiled binaries so they are not durable binary state

  Scenario: OCI pull serves an approved materialization
    Given an approved materialization exists for "hello-service:1.0.0"
    And VEX risk and policy allow serving it
    When an OCI client pulls "hello-service:1.0.0"
    Then the registry MUST resolve the source recipe
    And the registry MUST evaluate SBOM, CBOM, VEX, SLSA, scan, and policy metadata
    And the registry MUST stream bytes that match the advertised OCI descriptors
    And the OCI client MUST be able to complete the pull through standard OCI behavior

  Scenario: Metadata gate denies build and pull
    Given VEX risk, scan evidence, or policy marks "hello-service:1.0.0" as not allowed for the requested environment
    When an OCI client pulls "hello-service:1.0.0"
    Then the registry MUST NOT materialize the image
    And the registry MUST NOT stream derived image bytes
    And the registry MUST return an OCI-compliant error response
    And the registry SHOULD expose the denial reason through metadata, audit evidence, or policy logs

  Scenario: SBOM posture denies risky dependency metadata
    Given the latest SBOM evidence contains an unpinned dependency, missing integrity hash, direct dependency source, lifecycle script, or suspicious package script
    When an OCI client pulls "hello-service:1.0.0"
    Then the registry MUST deny materialization by default
    And the registry MUST preserve the SBOM finding as durable evidence
    And the registry MAY allow materialization only after an explicit policy exception or VEX-style triage record is attached

  Scenario: CBOM posture denies weak cryptography metadata
    Given the latest CBOM evidence contains private key material, legacy protocol use, weak algorithm use, weak key-size hints, or an EOL crypto library family
    When an OCI client pulls "hello-service:1.0.0"
    Then the registry MUST deny materialization by default
    And the registry MUST preserve the CBOM finding as durable evidence
    And the registry MAY allow materialization only after explicit cryptographic risk acceptance is recorded

  Scenario: SLSA posture denies weak provenance metadata
    Given the latest SLSA posture has an unpinned source revision, missing builder digest, undigested material, missing scan evidence, stale scan evidence, or failed build evidence
    When an OCI client pulls "hello-service:1.0.0"
    Then the registry MUST deny materialization by default
    And the registry MUST preserve the SLSA posture finding as durable evidence
    And the registry MUST expose the policy outcome in the SLSA predicate metadata

  Scenario: Binary output is derived and not preserved by default
    Given a push intake or explicit materialization produced image config and layer bytes
    When the registry has created metadata or streamed the requested bytes to the OCI client
    Then the registry MUST record metadata evidence for the intake or build
    And the registry MUST discard pushed or generated binary bytes
    And the registry MUST NOT preserve image layers, config blobs, compiled binaries, image archives, or intermediate outputs as durable state

  Scenario: Metadata is the durable registry state
    When a release is registered
    Then the registry MUST store source revision, builder identity, recipe digest, material digests, SBOM, CBOM, VEX, SLSA, policy status, and attestations
    And the registry MUST use metadata as the source of truth for later image materialization
    And the registry MUST NOT depend on previously retained binary blobs to prove traceability

  Scenario: SBOM drives component inventory
    Given the recipe includes locked software materials
    When the registry generates metadata for the release
    Then the registry MUST produce an SBOM describing expected software components
    And the SBOM SHOULD be attached as an OCI artifact
    And scanners MAY consume the SBOM without pulling derived image bytes

  Scenario: CBOM drives cryptographic inventory
    Given the recipe includes cryptographic materials or crypto-relevant configuration
    When the registry generates metadata for the release
    Then the registry MUST produce a CBOM describing expected algorithms, protocols, keys, certificates, or crypto policy
    And the CBOM SHOULD be attached as an OCI artifact
    And policy engines MAY consume the CBOM before image materialization

  Scenario: VEX drives exploitability decisions
    Given a vulnerability scanner reports a CVE for a component in the SBOM
    When a VEX statement exists for the recipe and source revision
    Then the registry MUST expose the VEX status as OCI metadata
    And the registry MUST use VEX and policy to decide whether materialization and pull are allowed
    And the registry MUST NOT treat component presence alone as proof of exploitability

  Scenario: SLSA records source-bound provenance
    Given a recipe has source, builder, materials, scans, and byproducts
    When an auditor requests SLSA provenance
    Then the registry MUST return an in-toto statement
    And the predicate type MUST be "https://slsa.dev/provenance/v1"
    And the predicate MUST include build definition, run details, resolved dependencies, and metadata byproduct digests
    And the predicate SHOULD include the fulcr SLSA posture policy outcome and findings

  Scenario: Standard OCI personas remain unchanged
    Given the client is an OCI runtime, orchestrator, scanner, auditor, or registry tool
    When the client uses standard OCI distribution flows
    Then the registry MUST present standard OCI resources and media types
    And the client SHOULD NOT need to understand the internal materialization mechanism
    And proprietary use-cases MAY exist only outside the OCI compatibility boundary

  Scenario: Storage savings are measurable
    Given repeated releases share source, materials, builders, or base layers
    When releases are registered in fulcr
    Then the registry MUST persist only metadata and evidence as durable state
    And the registry MUST avoid durable storage of unused binary layers
    And operators SHOULD measure saved storage against a conventional blob-preserving registry
```

## API Surface

The OCI API is the normative client contract. These endpoints MUST follow the OCI Distribution Specification:

```text
GET  /v2/
GET  /v2/<name>/manifests/<reference>
HEAD /v2/<name>/manifests/<reference>
GET  /v2/<name>/blobs/<digest>
HEAD /v2/<name>/blobs/<digest>
GET  /v2/<name>/referrers/<digest>
```

Push/upload endpoints are not implemented yet; this prototype currently accepts recipes and evidence through the metadata API and serves policy-gated OCI read paths.

Metadata API routes and OCI content routes require `Authorization: Bearer <fulcr_TOKEN>`. `/healthz` and `/v2/` remain open for local inspection.

The metadata API is an administrative interface for recipes, policy, and evidence. It MUST NOT replace OCI client compatibility:

```text
GET  /healthz
GET  /v1/recipes
POST /v1/recipes
GET  /v1/recipes/:id
POST /v1/recipes/:id/builds
GET  /v1/recipes/:id/builds
POST /v1/recipes/:id/scans
GET  /v1/recipes/:id/scans
GET  /v1/recipes/:id/scans/:scan_id
GET  /v1/recipes/:id/gate
GET  /v1/recipes/:id/sbom
GET  /v1/recipes/:id/cbom
POST /v1/recipes/:id/vex
GET  /v1/recipes/:id/vex
GET  /v1/recipes/:id/openvex
GET  /v1/recipes/:id/slsa
GET  /v1/recipes/:id/attestation
```

## Storage Policy

`fulcr` MUST make the virtual-image model measurable: protected materialization decisions, derived bytes served, durable metadata retained, and binary storage avoided.

The registry SHOULD measure and report:

- derived image bytes generated and streamed
- binary bytes discarded or intentionally not retained
- estimated storage avoided versus a conventional blob-preserving registry
- metadata size retained per image reference
- explicit materializations served by source revision and recipe digest
- denied materialization due to VEX, SBOM posture, CBOM posture, SLSA posture, scan findings, ad-hoc binaries, crypto drift, or metadata misalignment

This makes the value proposition observable: source and metadata become the durable image stub, policy decides whether bytes may exist, and `fulcr` keeps the proof instead of the pile of rarely reused binary blobs.

## Run

```bash
export fulcr_TOKEN=replace-with-local-token
cargo run -- --bind 127.0.0.1:8080 --data-dir .fulcr
```

Register a recipe:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/recipes \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $fulcr_TOKEN" \
  --data @examples/recipe.json | jq .
```

Create source scan evidence before materialization:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/recipes/<recipe-id>/scans \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $fulcr_TOKEN" \
  --data '{"mode":"source"}' | jq .
```

Add VEX metadata:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/recipes/<recipe-id>/vex \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $fulcr_TOKEN" \
  --data '{
    "vulnerability": "CVE-2026-1234",
    "status": "not_affected",
    "recipe_digest": "<recipe-digest-from-recipe-response>",
    "component": "example-lib",
    "justification": "vulnerable_code_not_present",
    "detail": "The vulnerable parser is excluded by this build profile.",
    "author": "platform-security"
  }' | jq .
```

Request SLSA provenance:

```bash
curl -sS http://127.0.0.1:8080/v1/recipes/<recipe-id>/slsa \
  -H "authorization: Bearer $fulcr_TOKEN" | jq .
```

Plan a materialization record without executing a build:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/recipes/<recipe-id>/builds \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $fulcr_TOKEN" \
  --data '{"execute": false}' | jq .
```

To pre-materialize an image before the first OCI manifest request, run the recipe build and cache its OCI layer artifact:

```bash
curl -sS -X POST http://127.0.0.1:8080/v1/recipes/<recipe-id>/builds \
  -H 'content-type: application/json' \
  -H "authorization: Bearer $fulcr_TOKEN" \
  --data '{"execute": true, "cache_artifact": true}' | jq .
```

Only run executable recipes from trusted local sources. `fulcr` is a prototype developer-protection registry, not a public multi-tenant build service.