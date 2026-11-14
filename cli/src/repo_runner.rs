//! Repository runner images (ADR 0216 decisions 2-5): the pinned tool catalog,
//! the build input file, the generated Dockerfiles, the `docker buildx bake`
//! definition that composes them, and the receipt `curie build --repo-runner`
//! prints.
//!
//! Everything here is pure: the command in `commands::repo_runner_build` runs
//! the build, and these functions decide what it runs.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The catalog version this binary builds.
pub const CATALOG_VERSION: u32 = 1;
/// Where the probe manifest lands in every repository runner image.
pub const MANIFEST_PATH: &str = "/etc/curie/tool-manifest.json";
/// Every repository runner image is built for both of these.
pub const PLATFORMS: [&str; 2] = ["linux/amd64", "linux/arm64"];
/// The repository the image is pushed to under `--registry`.
pub const IMAGE_NAME: &str = "curie-repo-runner";
/// Catalog v1: one object per entry, in catalog order, in the shape of
/// `docs/schemas/tool-catalog-entry.schema.json`.
pub const CATALOG_JSON: &str = include_str!("tool_catalog_v1.json");
/// The probe script run inside the composed image.
pub const PROBE_SCRIPT: &str = include_str!("repo_runner_probe.py");
/// The bake target that is built and pushed.
pub const BAKE_TARGET: &str = "curie-runner";

const CATALOG_TARGET: &str = "curie-catalog";
const REPOSITORY_TARGET: &str = "curie-repository";
const COMPOSED_CONTEXT: &str = "curie-composed";
const PROBE_OUT: &str = "/tmp/curie-tool-manifest.json";

/// One separately probed component of a catalog tool (#4485 decision 1).
///
/// `cargo fmt` and `cargo clippy` are components of `cargo`: distinct
/// executables under the tool's own binary, probed with their own commands, so
/// a manifest never claims `cargo` itself covers them.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogComponent {
    pub name: String,
    pub command: Vec<String>,
}

/// One pinned catalog tool.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    pub name: String,
    pub platforms: Vec<String>,
    pub source_digests: BTreeMap<String, String>,
    pub cache_env: BTreeMap<String, String>,
    pub registry_hosts: Vec<String>,
    pub probe: Vec<String>,
    #[serde(default)]
    pub components: Vec<CatalogComponent>,
}

/// The catalog, parsed once; catalog order is file order.
pub fn catalog() -> &'static [CatalogEntry] {
    static CATALOG: OnceLock<Vec<CatalogEntry>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(CATALOG_JSON).expect("the embedded tool catalog is valid JSON")
    })
}

fn catalog_names() -> String {
    catalog()
        .iter()
        .map(|e| e.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// An extra probe the repository declares beside its catalog tools.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeDecl {
    pub name: String,
    pub command: Vec<String>,
}

/// The build input file (YAML or JSON): the inputs of a binding's `runner` block.
#[derive(Debug, Clone, Default, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepoRunnerSpec {
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub dockerfile: Option<String>,
    #[serde(default)]
    pub probes: Vec<ProbeDecl>,
}

/// A parsed, validated input file and the paths it resolved to.
#[derive(Debug, Clone)]
pub struct LoadedSpec {
    pub spec: RepoRunnerSpec,
    /// The canonical directory holding the input file: the Dockerfile's build context.
    pub dir: PathBuf,
    /// The canonical Dockerfile, inside `dir`.
    pub dockerfile: Option<PathBuf>,
}

/// Parse an input file's text (YAML; JSON is YAML) and validate it.
pub fn parse_spec(text: &str) -> Result<RepoRunnerSpec> {
    let spec: RepoRunnerSpec =
        serde_norway::from_str(text).context("parse the repository runner input file")?;
    validate_spec(&spec)?;
    Ok(spec)
}

/// The refusals that need no filesystem, each naming the offending value.
pub fn validate_spec(spec: &RepoRunnerSpec) -> Result<()> {
    let mut seen = BTreeSet::new();
    for tool in &spec.tools {
        if !catalog().iter().any(|e| &e.name == tool) {
            bail!(
                "unknown tool {tool:?}; catalog v{CATALOG_VERSION} has {}",
                catalog_names()
            );
        }
        if !seen.insert(tool.as_str()) {
            bail!("tool {tool:?} is listed more than once");
        }
    }
    // Every selected catalog component name is also a probe name (#4485
    // decision 1): a declared probe may not reuse one, because the component
    // already probes it and the build records both under distinct names.
    let mut component_names = BTreeSet::new();
    for entry in selected_entries(spec) {
        for component in &entry.components {
            if component.name.trim().is_empty() {
                bail!(
                    "catalog tool {:?} declares a component with a blank name",
                    entry.name
                );
            }
            if let Some(first) = component.command.first() {
                if first.trim().is_empty() {
                    bail!(
                        "catalog tool {:?} component {:?} probes a blank executable",
                        entry.name,
                        component.name
                    );
                }
            } else {
                bail!(
                    "catalog tool {:?} component {:?} has an empty command",
                    entry.name,
                    component.name
                );
            }
            if !component_names.insert(component.name.as_str()) {
                bail!(
                    "component name {:?} is declared by more than one selected tool",
                    component.name
                );
            }
        }
    }
    let mut probe_names = component_names.clone();
    for probe in &spec.probes {
        if probe.name.trim().is_empty() {
            bail!("a probe has a blank name; every probe needs one");
        }
        let Some(argv0) = probe.command.first() else {
            bail!("probe {:?} has an empty command", probe.name);
        };
        if argv0.trim().is_empty() {
            bail!(
                "probe {:?} has a blank executable as its first command word",
                probe.name
            );
        }
        if component_names.contains(probe.name.as_str()) {
            bail!(
                "probe {:?} reuses a selected tool component's name, which already probes it",
                probe.name
            );
        }
        if !probe_names.insert(probe.name.as_str()) {
            bail!("probe name {:?} is used more than once", probe.name);
        }
        if seen.contains(probe.name.as_str()) {
            bail!(
                "probe {:?} has the name of a selected catalog tool, which already probes it",
                probe.name
            );
        }
    }
    if let Some(dockerfile) = &spec.dockerfile {
        if dockerfile.trim().is_empty() {
            bail!("dockerfile is blank; omit it or name a file beside the input file");
        }
    }
    Ok(())
}

/// Read and validate an input file, resolving its Dockerfile inside the file's
/// directory and checking that Dockerfile builds on `${CURIE_RUNNER_IMAGE}`.
pub fn load_spec(path: &Path) -> Result<LoadedSpec> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read the repository runner input file {}", path.display()))?;
    let canonical = path
        .canonicalize()
        .with_context(|| format!("resolve {}", path.display()))?;
    let dir = canonical
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent directory", canonical.display()))?
        .to_path_buf();
    let spec = parse_spec(&text).with_context(|| format!("{}", path.display()))?;
    let dockerfile = match &spec.dockerfile {
        Some(rel) => {
            let resolved = crate::connector_build::resolve_dockerfile(&dir, rel)
                .with_context(|| format!("{}: dockerfile {rel}", path.display()))?;
            let body = std::fs::read_to_string(&resolved)
                .with_context(|| format!("read {}", resolved.display()))?;
            crate::connector_build::check_runner_dockerfile(&body)
                .map_err(|error| anyhow!("{}: dockerfile {rel}: {error}", path.display()))?;
            Some(resolved)
        }
        None => None,
    };
    Ok(LoadedSpec {
        spec,
        dir,
        dockerfile,
    })
}

/// One probe the image build runs.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProbeRun {
    pub name: String,
    pub command: Vec<String>,
    /// `"catalog"` or `"probe"`.
    pub source: String,
}

/// The selected catalog entries, in catalog order regardless of input order.
pub fn selected_entries(spec: &RepoRunnerSpec) -> Vec<&'static CatalogEntry> {
    catalog()
        .iter()
        .filter(|e| spec.tools.contains(&e.name))
        .collect()
}

/// Selected catalog probes in catalog order, each tool's components right
/// after its own probe, then declared probes in order (#4485 decision 1).
pub fn probe_runs(spec: &RepoRunnerSpec) -> Vec<ProbeRun> {
    let mut runs: Vec<ProbeRun> = Vec::new();
    for entry in selected_entries(spec) {
        runs.push(ProbeRun {
            name: entry.name.clone(),
            command: entry.probe.clone(),
            source: "catalog".to_string(),
        });
        runs.extend(entry.components.iter().map(|component| ProbeRun {
            name: component.name.clone(),
            command: component.command.clone(),
            source: "catalog".to_string(),
        }));
    }
    runs.extend(spec.probes.iter().map(|p| ProbeRun {
        name: p.name.clone(),
        command: p.command.clone(),
        source: "probe".to_string(),
    }));
    runs
}

fn arch_of(platform: &str) -> &str {
    platform.rsplit('/').next().unwrap_or(platform)
}

/// `<ref>@sha256:<hex>` split into the reference and the hex.
fn split_pin(pinned: &str) -> (&str, &str) {
    pinned.split_once("@sha256:").unwrap_or((pinned, ""))
}

/// The per-platform image stages and the `${TARGETARCH}` selector for one entry.
fn image_source_stages(entry: &CatalogEntry) -> String {
    let mut out = String::new();
    for platform in &entry.platforms {
        if let Some(pinned) = entry.source_digests.get(platform) {
            out.push_str(&format!(
                "FROM {pinned} AS curie-tool-{}-{}\n",
                entry.name,
                arch_of(platform)
            ));
        }
    }
    out.push_str(&format!(
        "FROM curie-tool-{name}-${{TARGETARCH}} AS curie-tool-{name}\n",
        name = entry.name
    ));
    out
}

/// The source stage(s) an entry needs, or nothing when its digest only names
/// the suite its packages come from.
fn source_stages(entry: &CatalogEntry) -> String {
    match entry.name.as_str() {
        "build-essential" => String::new(),
        "pnpm" => {
            let pinned = entry
                .source_digests
                .get(PLATFORMS[0])
                .map(String::as_str)
                .unwrap_or_default();
            let (url, hex) = split_pin(pinned);
            format!(
                "FROM scratch AS curie-tool-pnpm\nADD --checksum=sha256:{hex} https://{url} /pnpm.tgz\n"
            )
        }
        _ => image_source_stages(entry),
    }
}

/// The layer an entry adds to the platform runner.
fn tool_layer(entry: &CatalogEntry) -> String {
    match entry.name.as_str() {
        "uv" => "COPY --from=curie-tool-uv /uv /uvx /usr/local/bin/\n".to_string(),
        "rust" => concat!(
            "COPY --from=curie-tool-rust /usr/local/cargo /usr/local/cargo\n",
            "COPY --from=curie-tool-rust /usr/local/rustup /usr/local/rustup\n",
            "ENV RUSTUP_HOME=/usr/local/rustup\n",
            "ENV PATH=\"/usr/local/cargo/bin:${PATH}\"\n",
            "RUN CARGO_HOME=/usr/local/cargo rustup component add rustfmt clippy \\\n",
            "    && cargo fmt --version && cargo clippy --version\n",
        )
        .to_string(),
        "pnpm" => concat!(
            "RUN --mount=type=bind,from=curie-tool-pnpm,source=/pnpm.tgz,target=/tmp/curie-pnpm.tgz \\\n",
            "    npm_config_cache=/tmp/curie-npm-cache npm install -g --ignore-scripts /tmp/curie-pnpm.tgz \\\n",
            "    && rm -rf /tmp/curie-npm-cache\n",
        )
        .to_string(),
        "build-essential" => concat!(
            "RUN apt-get update \\\n",
            "    && apt-get install -y --no-install-recommends build-essential cmake pkg-config \\\n",
            "    && rm -rf /var/lib/apt/lists/*\n",
        )
        .to_string(),
        "docker-cli" => concat!(
            "COPY --from=curie-tool-docker-cli /usr/local/bin/docker /usr/local/bin/docker\n",
            "COPY --from=curie-tool-docker-cli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose\n",
            "COPY --from=curie-tool-docker-cli /usr/local/libexec/docker/cli-plugins/docker-buildx /usr/local/libexec/docker/cli-plugins/docker-buildx\n",
            "RUN docker --version && docker compose version && docker buildx version\n",
        )
        .to_string(),
        other => unreachable!("catalog entry {other} has no layer"),
    }
}

/// The Dockerfile for the `curie-catalog` target: the platform runner plus the
/// selected catalog layers, in catalog order.
pub fn catalog_dockerfile(spec: &RepoRunnerSpec) -> String {
    let entries = selected_entries(spec);
    let mut out = String::from("ARG CURIE_PLATFORM_RUNNER\nARG TARGETARCH\n\n");
    for entry in &entries {
        let stages = source_stages(entry);
        if !stages.is_empty() {
            out.push_str(&stages);
            out.push('\n');
        }
    }
    out.push_str("FROM ${CURIE_PLATFORM_RUNNER}\nUSER root\n");
    for entry in &entries {
        out.push_str(&tool_layer(entry));
    }
    for entry in &entries {
        for (key, value) in &entry.cache_env {
            out.push_str(&format!("ENV {key}={value}\n"));
        }
    }
    out.push_str("USER 1000:1000\n");
    out
}

/// Each built platform's layer diff IDs from `docker buildx imagetools inspect
/// <ref> --format '{{json .Image}}'`: an object keyed by platform. Only
/// [`PLATFORMS`] keys are kept and each must carry `rootfs.diff_ids`.
pub fn platform_diff_ids(image_json: &str) -> Result<BTreeMap<String, Vec<String>>> {
    let value: serde_json::Value =
        serde_json::from_str(image_json).context("parse the image configs")?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("the image inspect output is not an object keyed by platform"))?;
    let mut out = BTreeMap::new();
    for (platform, entry) in object {
        if !PLATFORMS.contains(&platform.as_str()) {
            continue;
        }
        let ids = entry
            .pointer("/rootfs/diff_ids")
            .and_then(|v| v.as_array())
            .ok_or_else(|| anyhow!("{platform} has no rootfs.diff_ids in the image config"))?;
        let ids = ids
            .iter()
            .map(|id| {
                id.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow!("{platform} has a non-string diff id"))
            })
            .collect::<Result<Vec<_>>>()?;
        out.insert(platform.clone(), ids);
    }
    Ok(out)
}

/// Require, for every built platform, that the image's layers start with the
/// platform runner's layers, so the recorded base is what the image runs on.
pub fn check_builds_on_base(
    base: &BTreeMap<String, Vec<String>>,
    image: &BTreeMap<String, Vec<String>>,
) -> Result<()> {
    for platform in PLATFORMS {
        let (Some(base_ids), Some(image_ids)) = (base.get(platform), image.get(platform)) else {
            bail!(
                "{platform}: the platform runner or the built image has no layers for it; the \
                 repository runner Dockerfile's final stage does not build on \
                 ${{{}}}",
                crate::connector_build::RUNNER_BASE_ARG
            );
        };
        if !image_ids.starts_with(base_ids) {
            bail!(
                "{platform}: the built image's layers do not start with the platform runner's; \
                 the repository runner Dockerfile's final stage does not build on ${{{}}}",
                crate::connector_build::RUNNER_BASE_ARG
            );
        }
    }
    Ok(())
}

/// The probe stage and the final stage: the composed image plus exactly one
/// layer, the manifest the probe wrote. The probe stage sets `USER 1000:1000`
/// (the sandbox user) so the manifest reflects what that UID can run, whatever
/// USER the operator Dockerfile left. The probe list and docker flag travel as
/// a one-line JSON file written by a COPY heredoc, and the script reads only
/// its two path arguments, so no ARG or operator `ENV` can change what is
/// probed. The output path in `/tmp` is writable by that UID.
pub fn finalize_dockerfile(spec: &RepoRunnerSpec) -> String {
    let script = PROBE_SCRIPT.trim_end();
    let input = serde_json::json!({
        "docker_cli": spec.tools.iter().any(|t| t == "docker-cli"),
        "probes": probe_runs(spec),
    });
    let input = serde_json::to_string(&input).unwrap_or_default();
    format!(
        "FROM {COMPOSED_CONTEXT} AS curie-probe\n\
         USER 1000:1000\n\
         COPY <<'CURIE_PROBES' /tmp/curie-probes.json\n\
         {input}\n\
         CURIE_PROBES\n\
         COPY <<'CURIE_PROBE' /tmp/curie-probe.py\n\
         {script}\n\
         CURIE_PROBE\n\
         RUN python3 /tmp/curie-probe.py /tmp/curie-probes.json {PROBE_OUT}\n\
         \n\
         FROM {COMPOSED_CONTEXT}\n\
         COPY --from=curie-probe {PROBE_OUT} {MANIFEST_PATH}\n"
    )
}

/// Escape bake's interpolation openers so a string reaches the builder verbatim.
pub fn bake_escape(s: &str) -> String {
    s.replace("${", "$${").replace("%{", "%%{")
}

/// What one bake run builds.
#[derive(Debug, Clone)]
pub struct BakePlan {
    /// `<registry>/curie-repo-runner:r-<hex>`.
    pub image_ref: String,
    /// The digest-pinned platform runner, `<repo>@sha256:...`.
    pub base_ref: String,
    pub spec: RepoRunnerSpec,
    /// The operator Dockerfile: (context dir, Dockerfile path relative to it).
    pub dockerfile: Option<(PathBuf, String)>,
    /// A private empty directory, the context of the generated targets.
    pub empty_context: PathBuf,
}

fn escape_value(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    match value {
        Value::String(s) => Value::String(bake_escape(&s)),
        Value::Array(items) => Value::Array(items.into_iter().map(escape_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (bake_escape(&k), escape_value(v)))
                .collect(),
        ),
        other => other,
    }
}

/// The bake file: `curie-catalog`, optionally `curie-repository`, and
/// `curie-runner`, linked by `target:` contexts; only `curie-runner` is tagged
/// and pushed. Every string is escaped so bake does not interpolate it.
pub fn bake_definition(plan: &BakePlan) -> serde_json::Value {
    use serde_json::json;
    let empty = plan.empty_context.display().to_string();
    let mut targets = serde_json::Map::new();
    targets.insert(
        CATALOG_TARGET.to_string(),
        json!({
            "context": empty,
            "dockerfile-inline": catalog_dockerfile(&plan.spec),
            "args": {"CURIE_PLATFORM_RUNNER": plan.base_ref},
            "platforms": PLATFORMS,
        }),
    );
    let composed = match &plan.dockerfile {
        Some((context, dockerfile)) => {
            targets.insert(
                REPOSITORY_TARGET.to_string(),
                json!({
                    "context": context.display().to_string(),
                    "dockerfile": dockerfile,
                    "args": {(crate::connector_build::RUNNER_BASE_ARG): CATALOG_TARGET},
                    "contexts": {(CATALOG_TARGET): format!("target:{CATALOG_TARGET}")},
                    "platforms": PLATFORMS,
                }),
            );
            REPOSITORY_TARGET
        }
        None => CATALOG_TARGET,
    };
    targets.insert(
        BAKE_TARGET.to_string(),
        json!({
            "context": empty,
            "dockerfile-inline": finalize_dockerfile(&plan.spec),
            "contexts": {(COMPOSED_CONTEXT): format!("target:{composed}")},
            "platforms": PLATFORMS,
            "tags": [plan.image_ref],
            "output": ["type=registry"],
        }),
    );
    escape_value(json!({ "target": targets }))
}

/// The content tag: `r-` plus 16 hex of the sha256 of every build input.
/// Tool order in the input file is not an input; catalog order is.
pub fn input_tag(
    spec: &RepoRunnerSpec,
    dockerfile_digest: Option<&str>,
    base_digest: &str,
) -> String {
    let canonical = serde_json::json!({
        "catalog_version": CATALOG_VERSION,
        "entries": selected_entries(spec),
        "probes": spec.probes,
        "dockerfile_digest": dockerfile_digest,
        "base_digest": base_digest,
        "catalog_dockerfile": catalog_dockerfile(spec),
        "finalize_dockerfile": finalize_dockerfile(spec),
    });
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    let hex: String = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("r-{}", &hex[..16])
}

fn is_sha256_digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    })
}

/// `<repo>[:tag]@sha256:<64 hex>` to `sha256:<64 hex>`.
pub fn bare_digest(pinned: &str) -> Result<String> {
    match pinned.rsplit_once('@') {
        Some((_, digest)) if is_sha256_digest(digest) => Ok(digest.to_string()),
        _ => bail!("{pinned:?} is not pinned to a sha256 digest (`<repo>@sha256:<64 hex>`)"),
    }
}

/// The capability manifest's schema version (#4485 decision 2).
pub const CAPABILITY_MANIFEST_SCHEMA_VERSION: u32 = 1;
/// The `.github/` publication refusals the platform enforces (#4485 decision 3,
/// #4435): recorded verbatim so admission and validation see the exact
/// restriction, never a summary. `publications.py` holds the enforced strings.
pub const PUBLICATION_RESTRICTION_GITHUB: &str =
    "GitHub workflow changes cannot be published by this capability";
pub const PUBLICATION_RESTRICTION_GITHUB_METADATA: &str =
    "GitHub metadata changes cannot be published by this capability";

/// One executable the closed-world manifest records: its name, the version the
/// build's probe observed, and the exact probe command that observed it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ManifestToolProbe {
    pub name: String,
    pub version: String,
    pub probe_command: Vec<String>,
}

/// A connector the deployed bundle declares reachable, by name only (#4485
/// decision 2). Descriptive: no credential, address or grant travels.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeclaredConnector {
    pub name: String,
}

/// A service the deployed bundle declares reachable, by name only. Descriptive,
/// like [`DeclaredConnector`].
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeclaredService {
    pub name: String,
}

/// One verification check the bundle owns: its id, its route, and the
/// required PR CI check it delegates to when the route is delegated
/// (#4485 decision 4).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct VerificationCheck {
    pub id: String,
    pub route: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_to: Option<String>,
}

/// The actual built runner and bundle inputs a manifest derives from
/// (#4485 decisions 1-2). Everything here is observed or declared, never
/// inferred: `platform_tools` are the versions the image build's probe
/// observed, `verification_checks`/`connectors`/`services` come from the
/// bundle's own declarations.
#[derive(Debug, Clone)]
pub struct CapabilityManifestInputs {
    /// The built runner image's `sha256:` digest.
    pub image_digest: String,
    /// The deployed bundle's `sha256:` digest.
    pub bundle_digest: String,
    /// The build input the image was built from.
    pub spec: RepoRunnerSpec,
    /// Every platform tool the probe observed in the built image, in probe
    /// order: name, version, and the command that observed it.
    pub platform_tools: Vec<ManifestToolProbe>,
    /// The bundle's declared connectors, by name.
    pub connectors: Vec<DeclaredConnector>,
    /// The bundle's declared reachable services, by name.
    pub services: Vec<DeclaredService>,
    /// The bundle's own verification checks; empty when it declares none.
    pub verification_checks: Vec<VerificationCheck>,
    /// The sandbox egress class the deployed bundle runs under.
    pub egress_class: String,
}

/// The closed-world deployment manifest (#4485 decision 2): the exact
/// capabilities one built image and one deployed bundle had, bound to both
/// digests. Undeclared capability is absent; nothing here grants egress,
/// permission or credential.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CapabilityManifest {
    pub schema_version: u32,
    pub image_digest: String,
    pub bundle_digest: String,
    /// Every probed executable in probe order: catalog tools, their
    /// components, then declared probes.
    pub tools: Vec<ManifestToolProbe>,
    /// Registry hosts the selected catalog tools pull from. Probe inputs,
    /// never egress grants: a host here does not widen the sandbox.
    pub registry_hosts: Vec<String>,
    pub connectors: Vec<DeclaredConnector>,
    pub services: Vec<DeclaredService>,
    pub verification_checks: Vec<VerificationCheck>,
    pub egress_class: String,
    /// The exact `.github/` publication restriction strings the platform
    /// enforces (decision 3), workflow changes first.
    pub publication_restrictions: Vec<String>,
}

/// Derive the manifest from actual build and bundle inputs (#4485 decisions
/// 1-3). Refuses an image or bundle that is not pinned to a sha256 digest, so
/// the manifest always names an immutable deployment.
pub fn capability_manifest(inputs: &CapabilityManifestInputs) -> Result<CapabilityManifest> {
    if !is_sha256_digest(&inputs.image_digest) {
        bail!(
            "the runner image is not pinned to a sha256 digest ({:?}); a capability manifest \
             records only an immutable deployment",
            inputs.image_digest
        );
    }
    if !is_sha256_digest(&inputs.bundle_digest) {
        bail!(
            "the deployed bundle is not pinned to a sha256 digest ({:?}); a capability manifest \
             binds to the exact bundle",
            inputs.bundle_digest
        );
    }
    validate_spec(&inputs.spec)?;
    // Registry hosts come only from the selected catalog entries, in catalog
    // order, deduplicated: they are the hosts the image's own tool layers
    // pull from, which the probe needs, nothing wider.
    let mut registry_hosts: Vec<String> = Vec::new();
    for entry in selected_entries(&inputs.spec) {
        for host in &entry.registry_hosts {
            if !registry_hosts.contains(host) {
                registry_hosts.push(host.clone());
            }
        }
    }
    Ok(CapabilityManifest {
        schema_version: CAPABILITY_MANIFEST_SCHEMA_VERSION,
        image_digest: inputs.image_digest.clone(),
        bundle_digest: inputs.bundle_digest.clone(),
        tools: inputs.platform_tools.clone(),
        registry_hosts,
        connectors: inputs.connectors.clone(),
        services: inputs.services.clone(),
        verification_checks: inputs.verification_checks.clone(),
        egress_class: inputs.egress_class.clone(),
        publication_restrictions: vec![
            PUBLICATION_RESTRICTION_GITHUB.to_string(),
            PUBLICATION_RESTRICTION_GITHUB_METADATA.to_string(),
        ],
    })
}

/// The manifest's canonical bytes (#4485 decision 2): compact JSON with
/// sorted keys and a trailing newline, so identical inputs yield identical
/// bytes and the recorded digest is reproducible.
pub fn capability_manifest_bytes(manifest: &CapabilityManifest) -> Vec<u8> {
    let value = serde_json::to_value(manifest).expect("the manifest serializes");
    let mut sorted = serde_json::Map::new();
    for (key, item) in value.as_object().expect("the manifest is an object") {
        sorted.insert(key.clone(), item.clone());
    }
    let mut bytes = serde_json::to_vec(&serde_json::Value::Object(sorted))
        .expect("the canonical manifest serializes");
    bytes.push(b'\n');
    bytes
}

/// The sha256 hex digest of the manifest's canonical bytes.
pub fn capability_manifest_digest(manifest: &CapabilityManifest) -> String {
    let bytes = capability_manifest_bytes(manifest);
    let hex: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    hex
}

/// The commands the build must have observed probes for before the manifest is
/// recorded: every catalog tool probe, its components' probes, then declared
/// probes, in probe order (#4485 decision 1).
pub fn required_probe_commands(inputs: &CapabilityManifestInputs) -> Vec<Vec<String>> {
    probe_runs(&inputs.spec)
        .into_iter()
        .map(|run| run.command)
        .collect()
}

/// Fail a build that did not observe one required probe, naming the exact
/// command that did not answer (#4485 decision 1). The manifest is
/// closed-world evidence: a capability the build did not observe is absent,
/// and the build refuses to record a capability it did not observe.
pub fn require_probe(command: &[String], reason: &str) -> Result<()> {
    let Some(argv0) = command.first() else {
        bail!(
            "a required probe has a blank command; the build refuses to record a capability it \
             did not observe"
        );
    };
    if argv0.trim().is_empty() {
        bail!(
            "a required probe has a blank executable as its first command word; the build refuses \
             to record a capability it did not observe"
        );
    }
    let joined = command
        .iter()
        .map(|word| format!("{word:?}"))
        .collect::<Vec<_>>()
        .join(" ");
    bail!(
        "required probe `{joined}` failed: {reason}; the build refuses to record a capability it \
         did not observe"
    );
}

/// One binding the upgrade report flags: it lacks a matching capability record
/// for the image and bundle it currently runs (#4485 decision 6, AC5).
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LackingBinding {
    /// The binding's own name, as the Helm values name it.
    pub binding: String,
    /// The current runner image digest the binding deploys, when known.
    pub image_digest: Option<String>,
    /// The current deployed bundle digest, when known.
    pub bundle_digest: Option<String>,
    /// The action the operator takes: rebuild, render and redeploy this
    /// binding so its current image and bundle get a recorded manifest.
    pub action: String,
}

/// The upgrade report for a set of bindings (#4485 decision 6, AC5): each
/// active factory binding whose current image and bundle lack a matching
/// capability record, so the operator can regenerate and redeploy it before
/// manifest-based admission is enabled. A runner-image rebind alone does not
/// mark a binding ready: the record is bound to both the image AND the bundle
/// digests, so a rebind that keeps the old bundle stays in this list.
///
/// Pure: the caller reads which bindings exist and which records match, and
/// this decides the report. A binding is ready only when a recorded manifest
/// names exactly its current image and bundle digests.
pub fn upgrade_plan(bindings: &[BindingRecord]) -> Vec<LackingBinding> {
    bindings
        .iter()
        .filter(|binding| !binding.capability_recorded)
        .map(|binding| LackingBinding {
            binding: binding.name.clone(),
            image_digest: binding.image_digest.clone(),
            bundle_digest: binding.bundle_digest.clone(),
            action: format!(
                "rebuild the runner image, render the bundle and redeploy binding {:?} so its \
                 current image and bundle get a recorded capability manifest",
                binding.name
            ),
        })
        .collect()
}

/// One binding the upgrade report reads: its name, the image and bundle
/// digests it currently runs, and whether a recorded capability manifest
/// matches both (#4485 decision 6).
#[derive(Debug, Clone, PartialEq)]
pub struct BindingRecord {
    pub name: String,
    pub image_digest: Option<String>,
    pub bundle_digest: Option<String>,
    /// True only when a recorded manifest binds to exactly this image AND
    /// bundle digest. A runner-image rebind alone leaves it false.
    pub capability_recorded: bool,
}

/// Each platform's manifest digest from an OCI or Docker image index, skipping
/// attestation manifests. Exactly one `linux/amd64` and one `linux/arm64`
/// (variant `v8` or none) are required.
pub fn platform_digests_from_index(raw_index: &str) -> Result<BTreeMap<String, String>> {
    let index: serde_json::Value =
        serde_json::from_str(raw_index).context("parse the pushed image index")?;
    let manifests = index
        .get("manifests")
        .and_then(|m| m.as_array())
        .ok_or_else(|| {
            anyhow!("the pushed image is a single manifest, not a multi-platform index")
        })?;
    let mut out = BTreeMap::new();
    for manifest in manifests {
        let is_attestation = manifest
            .pointer("/annotations/vnd.docker.reference.type")
            .and_then(|v| v.as_str())
            == Some("attestation-manifest");
        if is_attestation {
            continue;
        }
        let Some(platform) = manifest.get("platform") else {
            continue;
        };
        let os = platform.get("os").and_then(|v| v.as_str()).unwrap_or("");
        let arch = platform
            .get("architecture")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let variant = platform.get("variant").and_then(|v| v.as_str());
        let key = match (os, arch, variant) {
            ("linux", "amd64", None) => "linux/amd64",
            ("linux", "arm64", None | Some("v8")) => "linux/arm64",
            _ => continue,
        };
        let digest = manifest
            .get("digest")
            .and_then(|v| v.as_str())
            .filter(|d| is_sha256_digest(d))
            .ok_or_else(|| anyhow!("the {key} manifest in the pushed index names no digest"))?;
        if out.insert(key.to_string(), digest.to_string()).is_some() {
            bail!("the pushed image index has more than one {key} manifest");
        }
    }
    for platform in PLATFORMS {
        if !out.contains_key(platform) {
            bail!("the pushed image index has no {platform} manifest");
        }
    }
    Ok(out)
}

/// The receipt's `runner` block, in the Helm values shape of
/// `factory.bindings[].repos[].runner`
/// (`charts/curie/values.schema.json#/definitions/repositoryRunner`), ready to paste.
#[derive(Debug, Clone, Serialize)]
pub struct RunnerRecord {
    pub tools: Vec<String>,
    /// `<repo>:<tag>@sha256:<index digest>`.
    pub image: String,
    /// The platform runner's `sha256:` digest.
    pub base: String,
    #[serde(rename = "platformDigests")]
    pub platform_digests: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub probes: Vec<ProbeDecl>,
}

/// The `curie build --repo-runner` receipt.
#[derive(Debug, Clone, Serialize)]
pub struct RepoRunnerBuildOutput {
    pub runner: RunnerRecord,
    pub platform_runner: String,
    pub catalog_version: u32,
    pub manifest_path: String,
}
