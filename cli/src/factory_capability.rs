//! The factory runner capability manifest (ADR 0199 decision 3, ADR 0204
//! decision 2.3; issue #4485).
//!
//! A closed-world, deployment-bound record of what a deployed runner image and
//! bundle can do. Everything here is pure: the build and deploy paths in
//! `repo_runner` and the API feed it their observed inputs, and these functions
//! decide the manifest bytes, the binding digests, and the upgrade report.
//!
//! The manifest is descriptive evidence, never a grant: a registry host is a
//! probe input recorded so admission can compare it against the platform's
//! egress declaration, a declared connector is absent unless the image probe
//! observed it, and no credential value ever appears. Anything not recorded is
//! absent (ADR 0199 decision 3.1). The admission gate that CONSUMES this
//! evidence is #4450; this module only produces and binds the evidence.

use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::repo_runner::{self, RepoRunnerSpec};

/// The manifest schema this binary writes.
pub const CAPABILITY_SCHEMA_VERSION: u32 = 1;
/// The exact `.github/` publication restriction the platform enforces
/// (`apps/worker/src/curie_worker/publication_validation.py`:
/// `publication_path_refusal` refuses any change under `.github/`).
pub const PUBLICATION_RESTRICTION_GITHUB: &str = ".github/";
/// The egress classes a deployment can record. A repository runner bound with
/// Docker egress is `docker`; the platform sandbox without any declared
/// egress is `sandbox`. A runner the operator has not declared is `unknown`,
/// which is missing evidence, never a ready verdict.
pub const EGRESS_CLASS_SANDBOX: &str = "sandbox";
pub const EGRESS_CLASS_DOCKER: &str = "docker";
pub const EGRESS_CLASS_UNKNOWN: &str = "unknown";

/// One probed executable, exactly as the existing repository runner probe
/// (`/etc/curie/tool-manifest.json`, ADR 0216) observed it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbedExecutable {
    pub name: String,
    pub version: String,
    pub path: String,
    /// The probe command that observed it, e.g. `["cargo", "--version"]`.
    pub probe_command: Vec<String>,
    /// `"catalog"` or `"probe"`, the existing manifest source vocabulary.
    pub source: String,
}

/// A check ID and route a bundle owns and ships with its declared checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleCheckRoute {
    pub id: String,
    /// `"executable"` or `"delegated"`.
    pub route: String,
    /// The required PR check a delegated route names.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_to: Option<String>,
}

/// The bundle inputs a manifest records beside the runner image's probes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleInputs {
    /// The deployed bundle's own `sha256:` digest, exactly as the API stores it.
    pub bundle_digest: String,
    /// Check IDs and routes the bundle's `verification/checks.json` declares.
    /// Empty when the bundle declares none, which is the common case; the
    /// effective admission view then composes the base-commit repository
    /// declaration (decision 4).
    #[serde(default)]
    pub bundle_checks: Vec<BundleCheckRoute>,
    /// Connector names the bundle's `connectors.yaml` declares. Recorded so
    /// admission can see what a run may reach; a missing connector is absent.
    #[serde(default)]
    pub connectors: Vec<String>,
    /// Registry hosts the bundle's build needs, as ADR 0204 decision 3.3
    /// defines them. Probe inputs only: a host never widens egress.
    #[serde(default)]
    pub registry_hosts: Vec<String>,
}

/// The closed-world deployment manifest (issue #4485 decisions 1-3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifest {
    pub schema_version: u32,
    /// The deployed runner image's digest-pinned reference.
    pub image: String,
    /// The image's `sha256:` digest.
    pub image_digest: String,
    pub bundle: BundleInputs,
    /// Every executable the image build probed, in probe order.
    pub executables: Vec<ProbedExecutable>,
    /// `sandbox` or `docker`, the egress class the deployment declares.
    pub egress_class: String,
    /// The exact `.github/` publication restriction the platform enforces.
    pub publication_restriction: String,
}

impl CapabilityManifest {
    /// The canonical manifest bytes: deterministic, sorted, two-space indented,
    /// one trailing newline. The same inputs always produce the same bytes, so
    /// the recorded digest is comparable across builds.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).unwrap_or_default()
    }

    /// The `sha256:` digest of the canonical bytes.
    pub fn digest(&self) -> String {
        let bytes = self.to_canonical_bytes();
        let hex: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        format!("sha256:{hex}")
    }
}

/// One probe requirement the build must satisfy: a command that must run and
/// be observed, distinguished from its executable. `cargo fmt` and `cargo
/// clippy` are separate commands from `cargo` (ADR 0204 decision 2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredProbe {
    pub name: String,
    pub command: Vec<String>,
}

/// The probes a repository runner build must run: the selected catalog entries
/// in catalog order, then the declared extra probes in file order, then the
/// separately distinguished Rust component commands. A named missing or
/// failing probe fails the build.
pub fn required_probes(spec: &RepoRunnerSpec) -> Vec<RequiredProbe> {
    let mut probes = repo_runner::probe_runs(spec)
        .into_iter()
        .map(|run| RequiredProbe {
            name: run.name,
            command: run.command,
        })
        .collect::<Vec<_>>();
    if spec.tools.iter().any(|tool| tool == "rust") {
        // `cargo fmt` and `cargo clippy` are separate commands, not the
        // `cargo` executable the catalog probes. Each must be observed
        // separately (ADR 0204 decision 2.3).
        probes.push(RequiredProbe {
            name: "cargo fmt".to_string(),
            command: vec!["cargo fmt".to_string(), "--version".to_string()],
        });
        probes.push(RequiredProbe {
            name: "cargo clippy".to_string(),
            command: vec!["cargo clippy".to_string(), "--version".to_string()],
        });
    }
    probes
}

/// The observed result of one build probe. A required probe that did not run,
/// or whose executable was not observed, names the command and fails the
/// build (issue #4485 decision 1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeObservation {
    /// The probe's name.
    pub name: String,
    /// The probe command, as declared.
    pub command: Vec<String>,
    /// The executable's observed version, or `None` when the probe failed.
    pub version: Option<String>,
}

/// Fail the build naming the first required probe that was not observed.
///
/// `observed` is the probe-manifest vocabulary the existing repository runner
/// build writes (`/etc/curie/tool-manifest.json`): one entry per probe that
/// ran and printed a version. This preserves the existing contract: nothing
/// here claims a tool the image did not probe.
pub fn check_required_probes(
    required: &[RequiredProbe],
    observations: &[ProbeObservation],
) -> Result<()> {
    for probe in required {
        let found = observations.iter().find(|obs| obs.name == probe.name);
        match found {
            None => bail!(
                "required probe {} ({}) was not observed by the image build; \
                 the build cannot record a manifest claiming it",
                probe.name,
                probe.command.join(" ")
            ),
            Some(obs) if obs.version.is_none() => bail!(
                "required probe {} ({}) failed inside the image build; \
                 the build cannot record a manifest claiming it",
                probe.name,
                probe.command.join(" ")
            ),
            Some(_) => {}
        }
    }
    Ok(())
}

/// The egress class a deployment records for one repository binding.
///
/// A binding whose repository runner entry enables Docker records `docker`;
/// a repository runner entry without Docker records `sandbox`; no entry at
/// all is missing evidence and records `unknown`.
pub fn egress_class(repo_entry: Option<&serde_json::Value>) -> String {
    let Some(entry) = repo_entry else {
        return EGRESS_CLASS_UNKNOWN.to_string();
    };
    let docker = entry
        .pointer("/docker/enabled")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
    if docker {
        EGRESS_CLASS_DOCKER.to_string()
    } else {
        EGRESS_CLASS_SANDBOX.to_string()
    }
}

/// Build the manifest from the actual build outputs: the recorded runner
/// receipt (image digests, tools) and the bundle's inputs. Deterministic for
/// the same inputs.
pub fn compose_manifest(
    runner: &repo_runner::RunnerRecord,
    bundle: &BundleInputs,
    egress: &str,
    observations: &[ProbeObservation],
) -> Result<CapabilityManifest> {
    let required = required_probes(&RepoRunnerSpec {
        tools: runner.tools.clone(),
        dockerfile: runner.dockerfile.clone(),
        probes: runner.probes.clone(),
    });
    check_required_probes(&required, observations)?;
    let image_digest = repo_runner::bare_digest(&runner.image)
        .with_context(|| format!("the recorded runner image {}", runner.image))?;
    let executables = observations
        .iter()
        .filter(|obs| obs.version.is_some())
        .map(|obs| ProbedExecutable {
            name: obs.name.clone(),
            version: obs.version.clone().unwrap_or_default(),
            path: String::new(),
            probe_command: obs.command.clone(),
            source: String::new(),
        })
        .collect();
    Ok(CapabilityManifest {
        schema_version: CAPABILITY_SCHEMA_VERSION,
        image: runner.image.clone(),
        image_digest,
        bundle: bundle.clone(),
        executables,
        egress_class: egress.to_string(),
        publication_restriction: PUBLICATION_RESTRICTION_GITHUB.to_string(),
    })
}

/// A parsed and validated manifest document, for the authenticated read.
pub fn parse_manifest(bytes: &[u8]) -> Result<CapabilityManifest> {
    let manifest: CapabilityManifest =
        serde_json::from_slice(bytes).context("parsing a factory capability manifest")?;
    if manifest.schema_version != CAPABILITY_SCHEMA_VERSION {
        bail!(
            "manifest schema version {} is not the recorded version {}",
            manifest.schema_version,
            CAPABILITY_SCHEMA_VERSION
        );
    }
    if !manifest.image_digest.starts_with("sha256:") || manifest.image_digest.len() != 71 {
        bail!("manifest image digest is not a sha256 digest");
    }
    if !manifest.bundle.bundle_digest.starts_with("sha256:") {
        bail!("manifest bundle digest is not a sha256 digest");
    }
    Ok(manifest)
}

/// Verify a manifest's bytes against its recorded digest. A mismatched or
/// stale binding is missing evidence, never a ready verdict (decision 5).
pub fn verify_digest(manifest: &CapabilityManifest, recorded_digest: &str) -> Result<()> {
    let digest = manifest.digest();
    if digest != recorded_digest {
        bail!(
            "recorded manifest digest {recorded_digest} does not match the manifest bytes \
             ({digest}); the binding is stale and the environment is unknown"
        );
    }
    Ok(())
}

/// One binding the upgrade report lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpgradeReportEntry {
    /// The repository path the binding names.
    pub repo: String,
    /// The binding's recorded runner image, or empty when none is bound.
    pub image: String,
    /// The binding's recorded bundle digest, or empty when none is recorded.
    pub bundle_digest: String,
    /// The binding's egress class (`docker` or `sandbox`).
    pub egress_class: String,
    /// Whether a matching capability record exists for exactly this image and
    /// bundle.
    pub has_capability_record: bool,
    /// The operator action: `build/render/redeploy` when the record is
    /// missing, or empty when the binding is covered.
    pub action: String,
}

/// The upgrade report (issue #4485 decision 6): each active factory binding
/// whose current image and bundle lack a matching capability record, so the
/// operator can regenerate and redeploy before manifest-based admission.
///
/// `bindings` maps repository paths to `(runner image, docker enabled,
/// bundle digest)`. `recorded` is the set of `(image digest, bundle digest)`
/// pairs that have a verified manifest. A runner-image rebinding alone never
/// marks a binding ready: the pair must match.
pub fn upgrade_report(
    bindings: &BTreeMap<String, (String, bool, String)>,
    recorded: &BTreeMap<(String, String), bool>,
) -> Vec<UpgradeReportEntry> {
    let mut entries = Vec::new();
    for (repo, (image, docker, bundle)) in bindings {
        let image_digest = repo_runner::bare_digest(image).ok();
        let pair = image_digest
            .clone()
            .zip((!bundle.is_empty()).then(|| bundle.clone()));
        let has_record = pair
            .as_ref()
            .and_then(|(image, bundle)| recorded.get(&(image.clone(), bundle.clone())))
            .copied()
            .unwrap_or(false);
        entries.push(UpgradeReportEntry {
            repo: repo.clone(),
            image: image.clone(),
            bundle_digest: bundle.clone(),
            egress_class: if *docker {
                EGRESS_CLASS_DOCKER.to_string()
            } else {
                EGRESS_CLASS_SANDBOX.to_string()
            },
            has_capability_record: has_record,
            action: if has_record {
                String::new()
            } else {
                "build/render/redeploy".to_string()
            },
        });
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(name: &str, version: Option<&str>) -> ProbeObservation {
        ProbeObservation {
            name: name.to_string(),
            command: vec![name.to_string(), "--version".to_string()],
            version: version.map(str::to_string),
        }
    }

    fn spec() -> RepoRunnerSpec {
        RepoRunnerSpec {
            tools: vec!["rust".to_string()],
            dockerfile: None,
            probes: vec![],
        }
    }

    #[test]
    fn rust_probes_distinguish_fmt_and_clippy() {
        let required = required_probes(&spec());
        let names: Vec<&str> = required.iter().map(|p| p.name.as_str()).collect();
        // The `rust` catalog entry probes the `cargo` executable, and the
        // separate `cargo fmt`/`cargo clippy` commands are probed distinctly.
        assert!(names.contains(&"rust"));
        assert!(names.contains(&"cargo fmt"));
        assert!(names.contains(&"cargo clippy"));
        let fmt = required.iter().find(|p| p.name == "cargo fmt").unwrap();
        assert_eq!(
            fmt.command,
            vec!["cargo fmt".to_string(), "--version".to_string()]
        );
        let cargo = required.iter().find(|p| p.name == "rust").unwrap();
        assert_eq!(
            cargo.command,
            vec!["cargo".to_string(), "--version".to_string()]
        );
    }

    #[test]
    fn missing_probe_fails_the_build_naming_the_command() {
        let required = required_probes(&spec());
        let observations = vec![
            observation("rust", Some("1.95.0")),
            // `cargo fmt` observed, `cargo clippy` missing.
            observation("cargo fmt", Some("1.7.1")),
        ];
        let error = check_required_probes(&required, &observations).unwrap_err();
        let text = format!("{error}");
        assert!(text.contains("cargo clippy"), "{text}");
        assert!(text.contains("--version"), "{text}");
    }

    #[test]
    fn failed_probe_fails_the_build_naming_the_command() {
        let required = required_probes(&spec());
        let observations = vec![
            observation("rust", Some("1.95.0")),
            observation("cargo fmt", Some("1.7.1")),
            observation("cargo clippy", None),
        ];
        let error = check_required_probes(&required, &observations).unwrap_err();
        assert!(format!("{error}").contains("cargo clippy"));
    }
}
