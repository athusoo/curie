//! Factory capability manifest regression tests (issue #4485).
//!
//! Covers, by outcome rather than internals:
//!
//! 1. The manifest is deterministic: the same runner receipt and bundle
//!    inputs produce byte-identical canonical bytes and the same digest, and
//!    a changed image or bundle digest changes the digest.
//! 2. A required probe that is missing or failed fails the build naming the
//!    command, and `cargo fmt`/`cargo clippy` are separate commands from the
//!    `cargo` executable the existing repository runner probe observes.
//! 3. The existing repository runner probe contract (`/etc/curie/tool-manifest.json`,
//!    ADR 0216) is unchanged: the catalog names, probe argv and manifest path
//!    the build uses are the ones in `cli/src/tool_catalog_v1.json`.
//! 4. The upgrade report names each active binding whose image and bundle
//!    lack a matching capability record, with the build/render/redeploy
//!    action; a runner-image rebinding alone never marks a binding ready.

use std::collections::BTreeMap;

use curie::factory_capability::{
    check_required_probes, compose_manifest, egress_class, parse_manifest, required_probes,
    upgrade_report, verify_digest, BundleCheckRoute, BundleInputs, CapabilityManifest,
    ProbeObservation, CAPABILITY_SCHEMA_VERSION, EGRESS_CLASS_DOCKER, EGRESS_CLASS_SANDBOX,
    EGRESS_CLASS_UNKNOWN, PUBLICATION_RESTRICTION_GITHUB,
};
use curie::repo_runner::{self, RepoRunnerSpec, RunnerRecord};
use serde_json::json;

const IMAGE_DIGEST: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const BUNDLE_DIGEST: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";
const OTHER_BUNDLE: &str =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const OTHER_IMAGE_DIGEST: &str =
    "sha256:4444444444444444444444444444444444444444444444444444444444444444";

fn runner(tools: &[&str]) -> RunnerRecord {
    RunnerRecord {
        tools: tools.iter().map(|t| t.to_string()).collect(),
        image: format!("ghcr.io/acme-corp/curie-repo-runner:t-1@{IMAGE_DIGEST}"),
        base: "sha256:5555555555555555555555555555555555555555555555555555555555555555".to_string(),
        platform_digests: BTreeMap::from([
            (
                "linux/amd64".to_string(),
                "sha256:6666666666666666666666666666666666666666666666666666666666666666"
                    .to_string(),
            ),
            (
                "linux/arm64".to_string(),
                "sha256:7777777777777777777777777777777777777777777777777777777777777777"
                    .to_string(),
            ),
        ]),
        dockerfile: None,
        probes: vec![],
    }
}

fn bundle_inputs(checks: &[(&str, &str)], registry_hosts: &[&str]) -> BundleInputs {
    BundleInputs {
        bundle_digest: BUNDLE_DIGEST.to_string(),
        bundle_checks: checks
            .iter()
            .map(|&(id, route)| BundleCheckRoute {
                id: id.to_string(),
                route: route.to_string(),
                delegated_to: (route == "delegated").then(|| format!("required-{id}")),
            })
            .collect(),
        connectors: vec![],
        registry_hosts: registry_hosts.iter().map(|h| h.to_string()).collect(),
    }
}

fn observations(rust: bool) -> Vec<ProbeObservation> {
    let mut all = vec![ProbeObservation {
        name: "uv".to_string(),
        command: vec!["uv".to_string(), "--version".to_string()],
        version: Some("0.10.7".to_string()),
    }];
    if rust {
        all.push(ProbeObservation {
            name: "rust".to_string(),
            command: vec!["cargo".to_string(), "--version".to_string()],
            version: Some("1.95.0".to_string()),
        });
        all.push(ProbeObservation {
            name: "cargo fmt".to_string(),
            command: vec!["cargo fmt".to_string(), "--version".to_string()],
            version: Some("rustfmt 1.7.1".to_string()),
        });
        all.push(ProbeObservation {
            name: "cargo clippy".to_string(),
            command: vec!["cargo clippy".to_string(), "--version".to_string()],
            version: Some("clippy 0.1.95".to_string()),
        });
    }
    all
}

#[test]
fn manifest_bytes_are_deterministic_and_bound_to_its_digests() {
    let inputs = runner(&["uv", "rust"]);
    let bundle = bundle_inputs(&[], &["index.crates.io", "pypi.org"]);
    let a = compose_manifest(&inputs, &bundle, EGRESS_CLASS_SANDBOX, &observations(true)).unwrap();
    let b = compose_manifest(&inputs, &bundle, EGRESS_CLASS_SANDBOX, &observations(true)).unwrap();
    // Stable bytes: the same inputs produce byte-identical canonical bytes.
    assert_eq!(a.to_canonical_bytes(), b.to_canonical_bytes());
    let digest = a.digest();
    assert_eq!(a.digest(), digest);
    // The manifest records the closed-world fields of decisions 1-3.
    assert_eq!(a.schema_version, CAPABILITY_SCHEMA_VERSION);
    assert_eq!(a.image_digest, IMAGE_DIGEST);
    assert_eq!(a.bundle.bundle_digest, BUNDLE_DIGEST);
    assert_eq!(a.publication_restriction, PUBLICATION_RESTRICTION_GITHUB);
    assert_eq!(a.egress_class, EGRESS_CLASS_SANDBOX);
    assert_eq!(
        a.bundle.registry_hosts,
        vec!["index.crates.io".to_string(), "pypi.org".to_string()]
    );
    // The recorded digest verifies against the exact bytes.
    verify_digest(&a, &digest).unwrap();
    // No credential value appears anywhere in the manifest bytes.
    let text = String::from_utf8(a.to_canonical_bytes()).unwrap();
    assert!(!text.to_lowercase().contains("token"), "{text}");
    assert!(!text.to_lowercase().contains("credential"), "{text}");
    assert!(!text.to_lowercase().contains("secret"), "{text}");
}

#[test]
fn a_changed_image_or_bundle_digest_changes_the_manifest_digest() {
    let inputs = runner(&["uv", "rust"]);
    let first = compose_manifest(
        &inputs,
        &bundle_inputs(&[], &[]),
        EGRESS_CLASS_SANDBOX,
        &observations(true),
    )
    .unwrap();
    let other_bundle = BundleInputs {
        bundle_digest: OTHER_BUNDLE.to_string(),
        ..bundle_inputs(&[], &[])
    };
    let second = compose_manifest(
        &inputs,
        &other_bundle,
        EGRESS_CLASS_SANDBOX,
        &observations(true),
    )
    .unwrap();
    let mut other_image = runner(&["uv", "rust"]);
    other_image.image = format!("ghcr.io/acme-corp/curie-repo-runner:t-1@{OTHER_IMAGE_DIGEST}");
    let third = compose_manifest(
        &other_image,
        &bundle_inputs(&[], &[]),
        EGRESS_CLASS_SANDBOX,
        &observations(true),
    )
    .unwrap();
    // Changed digests are different evidence: neither verifies against the
    // other's recorded digest, so a stale binding reads as unknown.
    assert_ne!(first.digest(), second.digest());
    assert_ne!(first.digest(), third.digest());
    assert!(verify_digest(&second, &first.digest()).is_err());
    assert!(verify_digest(&third, &first.digest()).is_err());
}

#[test]
fn a_missing_or_failed_required_probe_fails_the_build_naming_the_command() {
    let spec = RepoRunnerSpec {
        tools: vec!["rust".to_string()],
        dockerfile: None,
        probes: vec![],
    };
    let required = required_probes(&spec);
    // `cargo fmt` observed, `cargo clippy` missing entirely.
    let missing = vec![
        ProbeObservation {
            name: "rust".to_string(),
            command: vec!["cargo".to_string(), "--version".to_string()],
            version: Some("1.95.0".to_string()),
        },
        ProbeObservation {
            name: "cargo fmt".to_string(),
            command: vec!["cargo fmt".to_string(), "--version".to_string()],
            version: Some("rustfmt 1.7.1".to_string()),
        },
    ];
    let error = check_required_probes(&required, &missing).unwrap_err();
    let text = format!("{error}");
    assert!(text.contains("cargo clippy"), "{text}");
    assert!(text.contains("--version"), "{text}");
    // A probe that ran but failed names its command too.
    let mut failed = missing.clone();
    failed.push(ProbeObservation {
        name: "cargo clippy".to_string(),
        command: vec!["cargo clippy".to_string(), "--version".to_string()],
        version: None,
    });
    let error = check_required_probes(&required, &failed).unwrap_err();
    assert!(format!("{error}").contains("cargo clippy"));
    // Composing a manifest from incomplete probes refuses rather than
    // recording a claim the image did not prove.
    assert!(compose_manifest(
        &runner(&["rust"]),
        &bundle_inputs(&[], &[]),
        EGRESS_CLASS_SANDBOX,
        &missing
    )
    .is_err());
}

#[test]
fn rust_components_are_probed_separately_from_the_cargo_executable() {
    let spec = RepoRunnerSpec {
        tools: vec!["rust".to_string()],
        dockerfile: None,
        probes: vec![],
    };
    let required = required_probes(&spec);
    let names: Vec<&str> = required.iter().map(|p| p.name.as_str()).collect();
    // The `rust` catalog entry probes the `cargo` executable; `cargo fmt`
    // and `cargo clippy` are separate, named commands.
    assert!(names.contains(&"rust"));
    assert!(names.contains(&"cargo fmt"));
    assert!(names.contains(&"cargo clippy"));
    let cargo = required.iter().find(|p| p.name == "rust").unwrap();
    assert_eq!(
        cargo.command,
        vec!["cargo".to_string(), "--version".to_string()]
    );
    let fmt = required.iter().find(|p| p.name == "cargo fmt").unwrap();
    assert_eq!(
        fmt.command,
        vec!["cargo fmt".to_string(), "--version".to_string()]
    );
    // A bundle without the rust tool requires neither.
    let plain = required_probes(&RepoRunnerSpec::default());
    assert!(!plain.iter().any(|p| p.name.contains("cargo")));
    // A complete observation set composes.
    let manifest = compose_manifest(
        &runner(&["rust"]),
        &bundle_inputs(&[], &[]),
        EGRESS_CLASS_SANDBOX,
        &observations(true),
    )
    .unwrap();
    let names: Vec<&str> = manifest
        .executables
        .iter()
        .map(|e| e.name.as_str())
        .collect();
    assert!(names.contains(&"cargo fmt"));
    assert!(names.contains(&"cargo clippy"));
    assert!(names.contains(&"rust"));
}

#[test]
fn the_existing_repository_runner_probe_contract_is_preserved() {
    // The catalog is unchanged: v1 names, probe argv and the manifest path the
    // existing repository runner build relies on (ADR 0216).
    assert_eq!(repo_runner::CATALOG_VERSION, 1);
    assert_eq!(repo_runner::MANIFEST_PATH, "/etc/curie/tool-manifest.json");
    let names: Vec<&str> = repo_runner::catalog()
        .iter()
        .map(|e| e.name.as_str())
        .collect();
    assert_eq!(
        names,
        vec!["uv", "rust", "pnpm", "build-essential", "docker-cli"]
    );
    let rust = repo_runner::catalog()
        .iter()
        .find(|e| e.name == "rust")
        .unwrap();
    assert_eq!(
        rust.probe,
        vec!["cargo".to_string(), "--version".to_string()]
    );
    assert_eq!(
        rust.registry_hosts,
        vec![
            "index.crates.io".to_string(),
            "static.crates.io".to_string()
        ]
    );
    // required_probes reuses the same ordering source: catalog entries in
    // catalog order, then declared probes.
    let spec = RepoRunnerSpec {
        tools: vec!["rust".to_string(), "uv".to_string()],
        dockerfile: None,
        probes: vec![],
    };
    let required = required_probes(&spec);
    let names: Vec<&str> = required.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names.first(), Some(&"uv"));
    assert!(names.contains(&"rust"));
    // The existing ToolManifest shape still parses the committed schema.
    let manifest: CapabilityManifest = parse_manifest(
        &compose_manifest(
            &runner(&["uv"]),
            &bundle_inputs(&[], &[]),
            EGRESS_CLASS_DOCKER,
            &observations(false),
        )
        .unwrap()
        .to_canonical_bytes(),
    )
    .unwrap();
    assert_eq!(manifest.schema_version, CAPABILITY_SCHEMA_VERSION);
}

#[test]
fn a_bundle_declaring_checks_records_their_ids_and_routes() {
    let bundle = bundle_inputs(
        &[("api_checks", "delegated"), ("cli_checks", "executable")],
        &[],
    );
    let manifest = compose_manifest(
        &runner(&["uv"]),
        &bundle,
        EGRESS_CLASS_SANDBOX,
        &observations(false),
    )
    .unwrap();
    assert_eq!(manifest.bundle.bundle_checks.len(), 2);
    let api = manifest
        .bundle
        .bundle_checks
        .iter()
        .find(|c| c.id == "api_checks")
        .unwrap();
    assert_eq!(api.route, "delegated");
    assert_eq!(api.delegated_to.as_deref(), Some("required-api_checks"));
    let cli = manifest
        .bundle
        .bundle_checks
        .iter()
        .find(|c| c.id == "cli_checks")
        .unwrap();
    assert_eq!(cli.route, "executable");
    assert!(cli.delegated_to.is_none());
    // An empty bundle declaration composes too: the bundle owns no checks,
    // so admission composes the repository's base-commit declaration.
    let empty = compose_manifest(
        &runner(&["uv"]),
        &bundle_inputs(&[], &[]),
        EGRESS_CLASS_SANDBOX,
        &observations(false),
    )
    .unwrap();
    assert!(empty.bundle.bundle_checks.is_empty());
}

#[test]
fn the_egress_class_follows_the_binding_declaration() {
    let sandbox = json!({"runner": {"tools": ["uv"]}});
    let docker = json!({"runner": {"tools": ["uv", "docker-cli"]}, "docker": {"enabled": true}});
    let disabled = json!({"runner": {"tools": ["uv"]}, "docker": {"enabled": false}});
    assert_eq!(egress_class(Some(&sandbox)), EGRESS_CLASS_SANDBOX);
    assert_eq!(egress_class(Some(&docker)), EGRESS_CLASS_DOCKER);
    assert_eq!(egress_class(Some(&disabled)), EGRESS_CLASS_SANDBOX);
    // No binding entry is missing evidence, never a ready verdict.
    assert_eq!(egress_class(None), EGRESS_CLASS_UNKNOWN);
}

#[test]
fn a_malformed_manifest_or_mismatched_digest_is_unknown_not_ready() {
    let manifest = compose_manifest(
        &runner(&["uv"]),
        &bundle_inputs(&[], &[]),
        EGRESS_CLASS_SANDBOX,
        &observations(false),
    )
    .unwrap();
    // Malformed bytes refuse to parse.
    assert!(parse_manifest(b"{not json").is_err());
    // A mismatched digest is unknown: verification names the stale binding.
    let error = verify_digest(
        &manifest,
        "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    )
    .unwrap_err();
    let text = format!("{error}");
    assert!(text.contains("stale"), "{text}");
    // A wrong schema version refuses.
    let mut wrong = manifest.clone();
    wrong.schema_version = 2;
    assert!(parse_manifest(&wrong.to_canonical_bytes()).is_err());
}

#[test]
fn the_upgrade_report_names_bindings_without_a_matching_capability_record() {
    let mut bindings = BTreeMap::new();
    bindings.insert(
        "acme-corp/covered".to_string(),
        (
            format!("ghcr.io/acme/runner@{IMAGE_DIGEST}"),
            false,
            BUNDLE_DIGEST.to_string(),
        ),
    );
    bindings.insert(
        "acme-corp/legacy".to_string(),
        (
            "ghcr.io/acme/runner@sha256:9999999999999999999999999999999999999999999999999999999999999999"
                .to_string(),
            false,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ),
    );
    bindings.insert(
        "acme-corp/rebound".to_string(),
        (
            format!("ghcr.io/acme/runner@{OTHER_IMAGE_DIGEST}"),
            false,
            // The recorded manifest is for the OLD image, not this one.
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ),
    );
    let mut recorded = BTreeMap::new();
    recorded.insert((IMAGE_DIGEST.to_string(), BUNDLE_DIGEST.to_string()), true);
    recorded.insert(
        (
            "sha256:8888888888888888888888888888888888888888888888888888888888888888".to_string(),
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
        ),
        true,
    );
    let report = upgrade_report(&bindings, &recorded);
    let by_repo = |repo: &str| report.iter().find(|e| e.repo == repo).unwrap().clone();
    let covered = by_repo("acme-corp/covered");
    assert!(covered.has_capability_record);
    assert_eq!(covered.action, "");
    let legacy = by_repo("acme-corp/legacy");
    assert!(!legacy.has_capability_record);
    assert_eq!(legacy.action, "build/render/redeploy");
    // A runner-image rebinding alone does not mark a binding ready: the
    // recorded manifest for the old image pair does not cover the new one.
    let rebound = by_repo("acme-corp/rebound");
    assert!(!rebound.has_capability_record);
    assert_eq!(rebound.action, "build/render/redeploy");
}

#[test]
fn a_deployment_without_a_capability_record_is_missing_evidence_not_ready() {
    // The manifest cannot be composed for an image whose build never ran: a
    // record for a deployment created before capability recording reads as
    // missing evidence, never an inferred ready manifest.
    let empty = BTreeMap::new();
    let mut bindings = BTreeMap::new();
    bindings.insert(
        "acme-corp/pre-existing".to_string(),
        (
            format!("ghcr.io/acme/runner@{IMAGE_DIGEST}"),
            false,
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        ),
    );
    let report = upgrade_report(&bindings, &empty);
    assert_eq!(report.len(), 1);
    assert!(!report[0].has_capability_record);
    assert_eq!(report[0].action, "build/render/redeploy");
    // Recording a manifest for a new version does not mutate the old one:
    // the old binding's entry is unchanged, and only its exact pair flips.
    let mut recorded = BTreeMap::new();
    recorded.insert(
        (
            IMAGE_DIGEST.to_string(),
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".to_string(),
        ),
        true,
    );
    let report = upgrade_report(&bindings, &recorded);
    assert!(report[0].has_capability_record);
    assert_eq!(report[0].action, "");
}
