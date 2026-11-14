//! Integration: the closed-world capability manifest (#4485).
//!
//! Pins, by outcome rather than internals:
//!
//! 1. AC1: a deterministic manifest from the actual built runner and bundle
//!    inputs, bound to the image and bundle digests, recording every field of
//!    decisions 1-3, refusing an unpinned image or bundle, and failing a build
//!    that names the exact command when a required probe is missing or fails.
//!    `cargo fmt` and `cargo clippy` are recorded separately from the `cargo`
//!    executable. The existing repository runner probe contract
//!    (`probe_runs`, `validate_spec`) is preserved.
//! 2. AC5: the upgrade report identifies each active factory binding whose
//!    current image and bundle lack a matching capability record, with the
//!    build/render/redeploy action; a runner-image rebind alone does not mark
//!    a binding ready.
//!
//! The verification command is
//! `cargo test --manifest-path cli/Cargo.toml --test factory_capability_manifest`.

use curie::repo_runner::{
    capability_manifest, capability_manifest_bytes, capability_manifest_digest, probe_runs,
    require_probe, required_probe_commands, upgrade_plan, validate_spec, BindingRecord,
    CapabilityManifestInputs, DeclaredConnector, DeclaredService, ManifestToolProbe, ProbeDecl,
    RepoRunnerSpec, VerificationCheck, CAPABILITY_MANIFEST_SCHEMA_VERSION,
    PUBLICATION_RESTRICTION_GITHUB, PUBLICATION_RESTRICTION_GITHUB_METADATA,
};
use serde_json::{json, Value};

fn digest(c: char) -> String {
    format!("sha256:{}", c.to_string().repeat(64))
}

fn spec(tools: &[&str]) -> RepoRunnerSpec {
    RepoRunnerSpec {
        tools: tools.iter().map(|t| t.to_string()).collect(),
        ..RepoRunnerSpec::default()
    }
}

fn probe(name: &str, command: &[&str]) -> ProbeDecl {
    ProbeDecl {
        name: name.to_string(),
        command: command.iter().map(|c| c.to_string()).collect(),
    }
}

fn tool(name: &str, version: &str, command: &[&str]) -> ManifestToolProbe {
    ManifestToolProbe {
        name: name.to_string(),
        version: version.to_string(),
        probe_command: command.iter().map(|c| c.to_string()).collect(),
    }
}

/// Inputs whose manifest derives every field, in probe order.
fn full_inputs() -> CapabilityManifestInputs {
    CapabilityManifestInputs {
        image_digest: digest('a'),
        bundle_digest: digest('b'),
        spec: RepoRunnerSpec {
            tools: vec!["rust".to_string(), "uv".to_string()],
            dockerfile: None,
            probes: vec![probe("terraform", &["terraform", "version"])],
        },
        platform_tools: vec![
            tool("uv", "0.5.1", &["uv", "--version"]),
            tool("rust", "1.95.0", &["cargo", "--version"]),
            tool("cargo-fmt", "1.82.0", &["cargo", "fmt", "--version"]),
            tool("cargo-clippy", "0.1.82", &["cargo", "clippy", "--version"]),
            tool("terraform", "1.9.0", &["terraform", "version"]),
        ],
        connectors: vec![DeclaredConnector {
            name: "github".to_string(),
        }],
        services: vec![DeclaredService {
            name: "docker".to_string(),
        }],
        verification_checks: vec![VerificationCheck {
            id: "python".to_string(),
            route: "delegated".to_string(),
            delegated_to: Some("Python (ruff + mypy + pytest)".to_string()),
        }],
        egress_class: "egress-basic".to_string(),
    }
}

fn err_text<T>(result: anyhow::Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected a refusal"),
        Err(e) => format!("{e:#}"),
    }
}

// ---------------------------------------------------------------------------
// AC1: the manifest derives from actual build inputs
// ---------------------------------------------------------------------------

#[test]
fn manifest_records_every_field_in_decisions_1_to_3() {
    let manifest = capability_manifest(&full_inputs()).expect("full inputs derive a manifest");
    assert_eq!(manifest.schema_version, CAPABILITY_MANIFEST_SCHEMA_VERSION);
    assert_eq!(CAPABILITY_MANIFEST_SCHEMA_VERSION, 1);
    assert_eq!(manifest.image_digest, digest('a'));
    assert_eq!(manifest.bundle_digest, digest('b'));
    // Tools are the observed probes, in probe order.
    let names: Vec<&str> = manifest.tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(
        names,
        ["uv", "rust", "cargo-fmt", "cargo-clippy", "terraform"]
    );
    assert_eq!(manifest.tools[0].version, "0.5.1");
    assert_eq!(manifest.tools[0].probe_command, ["uv", "--version"]);
    // Registry hosts come only from the selected catalog entries, deduped,
    // in catalog order (uv then rust).
    assert_eq!(
        manifest.registry_hosts,
        [
            "pypi.org",
            "files.pythonhosted.org",
            "index.crates.io",
            "static.crates.io",
        ]
    );
    assert_eq!(
        manifest.connectors,
        [DeclaredConnector {
            name: "github".to_string()
        }]
    );
    assert_eq!(
        manifest.services,
        [DeclaredService {
            name: "docker".to_string()
        }]
    );
    assert_eq!(manifest.verification_checks.len(), 1);
    assert_eq!(manifest.verification_checks[0].id, "python");
    assert_eq!(
        manifest.verification_checks[0].delegated_to.as_deref(),
        Some("Python (ruff + mypy + pytest)")
    );
    assert_eq!(manifest.egress_class, "egress-basic");
    // Decision 3: the exact `.github/` refusals, workflow changes first.
    assert_eq!(
        manifest.publication_restrictions,
        [
            PUBLICATION_RESTRICTION_GITHUB.to_string(),
            PUBLICATION_RESTRICTION_GITHUB_METADATA.to_string(),
        ]
    );
}

#[test]
fn the_recorded_github_restrictions_match_the_platform_refusals() {
    // Decision 3: the manifest records the restriction verbatim, so it must
    // equal the strings the platform enforces, never a summary.
    assert_eq!(
        PUBLICATION_RESTRICTION_GITHUB,
        "GitHub workflow changes cannot be published by this capability"
    );
    assert_eq!(
        PUBLICATION_RESTRICTION_GITHUB_METADATA,
        "GitHub metadata changes cannot be published by this capability"
    );
}

#[test]
fn manifest_bytes_are_stable_and_sorted_and_end_in_one_newline() {
    let manifest = capability_manifest(&full_inputs()).expect("full inputs derive a manifest");
    let bytes = capability_manifest_bytes(&manifest);
    let again = capability_manifest_bytes(&manifest);
    assert_eq!(bytes, again, "identical inputs yield identical bytes");
    assert_eq!(
        bytes.last(),
        Some(&b'\n'),
        "canonical bytes end in a newline"
    );
    assert_eq!(
        bytes.iter().filter(|b| **b == b'\n').count(),
        1,
        "one line, compact"
    );
    let text = String::from_utf8(bytes.clone()).expect("canonical bytes are UTF-8");
    assert!(!text.contains(": "), "compact JSON has no spaces");
    let value: Value = serde_json::from_str(text.trim()).expect("canonical bytes parse");
    let keys: Vec<&str> = value
        .as_object()
        .expect("the manifest is an object")
        .keys()
        .map(|k| k.as_str())
        .collect();
    let mut sorted = keys.clone();
    sorted.sort();
    assert_eq!(keys, sorted, "keys are sorted");
    assert_eq!(
        keys,
        [
            "bundle_digest",
            "connectors",
            "egress_class",
            "image_digest",
            "publication_restrictions",
            "registry_hosts",
            "schema_version",
            "services",
            "tools",
            "verification_checks",
        ]
    );
}

#[test]
fn a_changed_input_changes_the_digest_and_identical_inputs_do_not() {
    let base = capability_manifest(&full_inputs()).expect("full inputs derive a manifest");
    let base_digest = capability_manifest_digest(&base);
    // Stable for identical inputs.
    let same = capability_manifest(&full_inputs()).expect("same inputs derive a manifest");
    assert_eq!(capability_manifest_digest(&same), base_digest);
    assert_eq!(capability_manifest_digest(&base), hex64_predicate(&base));
    // Changed image digest -> changed manifest digest.
    let mut changed = full_inputs();
    changed.image_digest = digest('c');
    let other = capability_manifest(&changed).expect("a pinned image derives a manifest");
    assert_ne!(capability_manifest_digest(&other), base_digest);
    // Changed bundle digest -> changed digest.
    let mut changed = full_inputs();
    changed.bundle_digest = digest('d');
    let other = capability_manifest(&changed).expect("a pinned bundle derives a manifest");
    assert_ne!(capability_manifest_digest(&other), base_digest);
    // Changed observed version -> changed digest: the manifest is evidence of
    // the build's probes, so a drifted probe is a different deployment.
    let mut changed = full_inputs();
    changed.platform_tools[1].version = "1.83.0".to_string();
    let other = capability_manifest(&changed).expect("observed tools derive a manifest");
    assert_ne!(capability_manifest_digest(&other), base_digest);
}

/// The digest is the sha256 hex of the canonical bytes.
fn hex64_predicate(manifest: &curie::repo_runner::CapabilityManifest) -> String {
    let bytes = capability_manifest_bytes(manifest);
    use sha2::{Digest, Sha256};
    Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[test]
fn manifest_refuses_an_unpinned_image_or_bundle() {
    // An unpinned image is refused, naming it.
    let mut inputs = full_inputs();
    inputs.image_digest = "curie-repo-runner:latest".to_string();
    let msg = err_text(capability_manifest(&inputs));
    assert!(msg.contains("runner image"), "{msg}");
    assert!(msg.contains("sha256"), "{msg}");
    // An unpinned bundle is refused too.
    let mut inputs = full_inputs();
    inputs.bundle_digest = "sha256:short".to_string();
    let msg = err_text(capability_manifest(&inputs));
    assert!(msg.contains("bundle"), "{msg}");
    // A well-formed sha256 that is not 64 hex is refused.
    let mut inputs = full_inputs();
    inputs.image_digest = "sha256:zz".to_string();
    assert!(capability_manifest(&inputs).is_err());
    // The neighbour: both pinned derive a manifest.
    capability_manifest(&full_inputs()).expect("both pinned derive a manifest");
}

#[test]
fn manifest_refuses_an_invalid_spec_exactly_like_the_build() {
    let mut inputs = full_inputs();
    inputs.spec = spec(&["uv", "node"]);
    let msg = err_text(capability_manifest(&inputs));
    assert!(msg.contains("node"), "{msg}");
    // The manifest derives from the SAME validation the build ran, so an
    // invalid spec can never reach a recorded manifest.
    assert!(err_text(validate_spec(&inputs.spec)).contains("node"));
}

#[test]
fn required_probe_commands_are_every_probe_in_probe_order() {
    let inputs = full_inputs();
    let commands = required_probe_commands(&inputs);
    // Catalog tools in catalog order (uv, rust), each tool's components right
    // after its own probe, then declared probes.
    assert_eq!(
        commands,
        vec![
            vec!["uv".to_string(), "--version".to_string()],
            vec!["cargo".to_string(), "--version".to_string()],
            vec![
                "cargo".to_string(),
                "fmt".to_string(),
                "--version".to_string()
            ],
            vec![
                "cargo".to_string(),
                "clippy".to_string(),
                "--version".to_string()
            ],
            vec!["terraform".to_string(), "version".to_string()],
        ]
    );
    // The same commands probe_runs runs: the manifest's closed world is the
    // probes the build executes, not a second list.
    let runs = probe_runs(&inputs.spec);
    assert_eq!(commands.len(), runs.len());
}

#[test]
fn require_probe_fails_naming_the_exact_command() {
    let cargo_fmt = vec![
        "cargo".to_string(),
        "fmt".to_string(),
        "--version".to_string(),
    ];
    let msg = err_text(require_probe(&cargo_fmt, "exit status 1"));
    assert!(msg.contains("\"cargo\""), "{msg}");
    assert!(msg.contains("\"fmt\""), "{msg}");
    assert!(msg.contains("--version"), "{msg}");
    assert!(msg.contains("exit status 1"), "{msg}");
    // An empty command is refused, never silently observed.
    let msg = err_text(require_probe(&[], "no such executable"));
    assert!(msg.to_lowercase().contains("blank"), "{msg}");
    // A blank executable as the first word is refused too.
    let blank = vec!["   ".to_string(), "--version".to_string()];
    let msg = err_text(require_probe(&blank, "no such executable"));
    assert!(msg.to_lowercase().contains("blank"), "{msg}");
}

#[test]
fn cargo_fmt_and_clippy_are_components_distinct_from_cargo() {
    // Decision 1: the catalog records `cargo fmt` and `cargo clippy` as
    // components of `cargo`, probed with their own commands, so a manifest
    // never claims the `cargo` probe covers them.
    let rust = curie::repo_runner::catalog()
        .iter()
        .find(|e| e.name == "rust")
        .expect("catalog v1 has rust");
    let components: Vec<(&str, Vec<String>)> = rust
        .components
        .iter()
        .map(|c| (c.name.as_str(), c.command.clone()))
        .collect();
    assert_eq!(
        components.len(),
        2,
        "cargo has exactly the fmt and clippy components"
    );
    assert_eq!(components[0].0, "cargo-fmt");
    assert_eq!(components[0].1, ["cargo", "fmt", "--version"]);
    assert_eq!(components[1].0, "cargo-clippy");
    assert_eq!(components[1].1, ["cargo", "clippy", "--version"]);
    // None of them reuses the tool's own name.
    assert!(rust.components.iter().all(|c| c.name != "cargo"));
    // And the probe order interleaves: the tool, then its components.
    let runs = probe_runs(&spec(&["rust"]));
    let names: Vec<&str> = runs.iter().map(|r| r.name.as_str()).collect();
    assert_eq!(names, ["rust", "cargo-fmt", "cargo-clippy"]);
}

#[test]
fn the_existing_repository_runner_probe_contract_is_preserved() {
    // The pre-#4485 contract: selected catalog tools probe in catalog order,
    // then declared probes, with the same refusals.
    let runs = probe_runs(&RepoRunnerSpec {
        tools: vec!["uv".to_string()],
        dockerfile: None,
        probes: vec![probe("terraform", &["terraform", "version"])],
    });
    let names: Vec<(&str, &str)> = runs
        .iter()
        .map(|r| (r.name.as_str(), r.source.as_str()))
        .collect();
    assert_eq!(names, [("uv", "catalog"), ("terraform", "probe")]);
    // A declared probe may not reuse a selected tool's name...
    let shadow = RepoRunnerSpec {
        tools: vec!["uv".to_string()],
        dockerfile: None,
        probes: vec![probe("uv", &["uv", "--version"])],
    };
    let msg = err_text(validate_spec(&shadow));
    assert!(msg.contains("uv"), "{msg}");
    // ...nor a component's name (#4485): `cargo-fmt` already probes it.
    let shadow = RepoRunnerSpec {
        tools: vec!["rust".to_string()],
        dockerfile: None,
        probes: vec![probe("cargo-fmt", &["cargo", "fmt", "--version"])],
    };
    let msg = err_text(validate_spec(&shadow));
    assert!(msg.contains("cargo-fmt"), "{msg}");
    // Duplicate probe names are still refused.
    let dup = RepoRunnerSpec {
        tools: vec![],
        dockerfile: None,
        probes: vec![probe("chk", &["a"]), probe("chk", &["b"])],
    };
    let msg = err_text(validate_spec(&dup));
    assert!(msg.contains("chk"), "{msg}");
    // A spec without tools or probes is still valid.
    validate_spec(&RepoRunnerSpec::default()).expect("the empty spec is valid");
    // The catalog's five names and platforms are unchanged.
    let names: Vec<&str> = curie::repo_runner::catalog()
        .iter()
        .map(|e| e.name.as_str())
        .collect();
    assert_eq!(
        names,
        ["uv", "rust", "pnpm", "build-essential", "docker-cli"]
    );
}

#[test]
fn registry_hosts_deduplicate_across_selected_tools() {
    // `rust` and `uv` both name crates hosts; `uv` adds astral.sh. Selecting
    // both keeps each host once, in catalog order.
    let inputs = full_inputs();
    let manifest = capability_manifest(&inputs).expect("full inputs derive a manifest");
    assert_eq!(manifest.registry_hosts.len(), 4);
    assert!(
        manifest
            .registry_hosts
            .iter()
            .filter(|h| *h == "index.crates.io")
            .count()
            == 1,
        "duplicate hosts are collapsed"
    );
    // An unselected tool contributes nothing.
    let mut sparse = full_inputs();
    sparse.spec.tools = vec!["uv".to_string()];
    let manifest = capability_manifest(&sparse).expect("uv alone derives a manifest");
    assert_eq!(
        manifest.registry_hosts,
        ["pypi.org", "files.pythonhosted.org"]
    );
}

#[test]
fn a_missing_connector_service_or_check_is_absent_never_inferred() {
    let mut inputs = full_inputs();
    inputs.connectors = vec![];
    inputs.services = vec![];
    inputs.verification_checks = vec![];
    let manifest = capability_manifest(&inputs).expect("absent declarations derive a manifest");
    assert!(manifest.connectors.is_empty());
    assert!(manifest.services.is_empty());
    assert!(manifest.verification_checks.is_empty());
    // None of the absent declarations leaks into the bytes.
    let text = String::from_utf8(capability_manifest_bytes(&manifest)).expect("UTF-8");
    let value: Value = serde_json::from_str(text.trim()).expect("the bytes parse");
    assert_eq!(value["connectors"], json!([]));
    assert_eq!(value["services"], json!([]));
    assert_eq!(value["verification_checks"], json!([]));
    // The observed tools are still there.
    assert_eq!(value["tools"].as_array().expect("tools").len(), 5);
}

#[test]
fn the_manifest_serializes_every_field_under_its_json_name() {
    let manifest = capability_manifest(&full_inputs()).expect("full inputs derive a manifest");
    let value = serde_json::to_value(&manifest).expect("the manifest serializes");
    let object = value.as_object().expect("the manifest is an object");
    assert_eq!(object["schema_version"], json!(1));
    assert_eq!(object["image_digest"], json!(digest('a')));
    assert_eq!(object["bundle_digest"], json!(digest('b')));
    // A check without a delegation omits the field entirely.
    let check = &object["verification_checks"][0];
    assert_eq!(
        check["delegated_to"],
        json!("Python (ruff + mypy + pytest)")
    );
    let mut bare = full_inputs();
    bare.verification_checks = vec![VerificationCheck {
        id: "rust".to_string(),
        route: "sandbox".to_string(),
        delegated_to: None,
    }];
    let manifest = capability_manifest(&bare).expect("bare inputs derive a manifest");
    let value = serde_json::to_value(&manifest).expect("the manifest serializes");
    assert!(
        value["verification_checks"][0]
            .get("delegated_to")
            .is_none(),
        "an undelegated check omits delegated_to: {value}"
    );
}

// ---------------------------------------------------------------------------
// AC5: the upgrade report
// ---------------------------------------------------------------------------

fn binding(name: &str, image: Option<char>, bundle: Option<char>, recorded: bool) -> BindingRecord {
    BindingRecord {
        name: name.to_string(),
        image_digest: image.map(digest),
        bundle_digest: bundle.map(digest),
        capability_recorded: recorded,
    }
}

#[test]
fn the_upgrade_plan_lists_each_lacking_binding_with_its_action() {
    let plan = upgrade_plan(&[
        binding("web", Some('a'), Some('b'), true),
        binding("jobs", Some('c'), Some('d'), false),
        binding("docs", None, None, false),
    ]);
    assert_eq!(plan.len(), 2, "ready bindings are not listed");
    assert_eq!(plan[0].binding, "jobs");
    assert_eq!(plan[0].image_digest, Some(digest('c')));
    assert_eq!(plan[0].bundle_digest, Some(digest('d')));
    assert!(plan[0].action.contains("redeploy"), "{}", plan[0].action);
    assert!(plan[0].action.contains("jobs"), "{}", plan[0].action);
    // An unknown-digest binding is still listed, with its unknowns.
    assert_eq!(plan[1].binding, "docs");
    assert_eq!(plan[1].image_digest, None);
    assert_eq!(plan[1].bundle_digest, None);
}

#[test]
fn a_runner_image_rebind_alone_does_not_mark_a_binding_ready() {
    // Decision 6 / AC5: the record binds to BOTH the image and the bundle.
    // A binding that rebound its runner image but kept its old bundle has no
    // matching record, so the report still lists it.
    let plan = upgrade_plan(&[
        // Recorded for exactly the current image AND bundle: ready.
        binding("matched", Some('a'), Some('b'), true),
        // The old image's record no longer matches the new image: lacking.
        binding("rebound", Some('x'), Some('b'), false),
    ]);
    assert_eq!(
        plan.iter().map(|b| b.binding.as_str()).collect::<Vec<_>>(),
        ["rebound"],
        "only the image-matched binding is ready"
    );
    // The report names the digests it lacked a record for.
    assert_eq!(plan[0].image_digest, Some(digest('x')));
    assert_eq!(plan[0].bundle_digest, Some(digest('b')));
}

#[test]
fn an_empty_plan_when_every_binding_has_a_matching_record() {
    let plan = upgrade_plan(&[binding("one", Some('a'), Some('b'), true)]);
    assert!(plan.is_empty());
    assert!(upgrade_plan(&[]).is_empty());
}
