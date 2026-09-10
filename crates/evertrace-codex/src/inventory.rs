//! Closed interpretation of the fixed native finite-assets profile.
//! Filesystem/process authority belongs to the daemon, not these input values.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryHostObservation {
    pub home: PathBuf,
    pub config_root: PathBuf,
    pub cwd: PathBuf,
    pub profile: Option<String>,
    pub selections_observed: bool,
}

impl InventoryHostObservation {
    pub fn validate(&self) -> Result<(), InventoryParseError> {
        for path in [&self.home, &self.config_root, &self.cwd] {
            if !path
                .to_str()
                .is_some_and(crate::binding::valid_lexical_absolute_path)
            {
                return Err(InventoryParseError);
            }
        }
        if self.profile.as_ref().is_some_and(|value| {
            value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
        }) {
            return Err(InventoryParseError);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FiniteSourceSelection {
    pub instruction_fallback_names: Vec<String>,
    pub root_markers: Vec<String>,
    pub user_instruction_file: Option<PathBuf>,
    pub enabled_plugins: BTreeMap<String, bool>,
    pub plugins_enabled: bool,
    pub project_doc_max_bytes: u64,
    pub skill_rules: Vec<SkillSelectionRule>,
    pub source_overrides_present: bool,
    pub observed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SkillSelector {
    Path(PathBuf),
    Name(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SkillSelectionRule {
    pub selector: SkillSelector,
    pub enabled: bool,
}

impl FiniteSourceSelection {
    pub fn skill_enabled(&self, path: &Path, name: &str) -> bool {
        self.skill_rules
            .iter()
            .rev()
            .find_map(|rule| {
                let matches = match &rule.selector {
                    SkillSelector::Path(selected) => selected == path,
                    SkillSelector::Name(selected) => selected == name,
                };
                matches.then_some(rule.enabled)
            })
            .unwrap_or(true)
    }
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[error("finite Host source selection is unavailable")]
pub struct InventoryParseError;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum InventoryAssetError {
    #[error("invalid finite asset")]
    Invalid,
    #[error("unsupported finite asset syntax")]
    Unsupported,
}

pub fn selected_profile(
    bytes: &[u8],
    requested: Option<&str>,
) -> Result<Option<String>, InventoryParseError> {
    let value: toml::Value =
        toml::from_str(std::str::from_utf8(bytes).map_err(|_| InventoryParseError)?)
            .map_err(|_| InventoryParseError)?;
    let selected = match requested {
        Some(value) => Some(value),
        None => value
            .get("profile")
            .map(|value| value.as_str().ok_or(InventoryParseError))
            .transpose()?,
    };
    if let Some(selected) = selected
        && (selected.is_empty()
            || selected.len() > 128
            || selected.chars().any(char::is_control)
            || value
                .get("profiles")
                .and_then(|profiles| profiles.get(selected))
                .and_then(toml::Value::as_table)
                .is_none())
    {
        return Err(InventoryParseError);
    }
    Ok(selected.map(ToOwned::to_owned))
}

/// Parses only source selectors in one already-authorized config layer. The
/// caller rejects unsupported layers; this is not a merged Host configuration.
/// Unrelated configuration is neither copied nor interpreted.
pub fn source_selection(
    bytes: &[u8],
    profile: Option<&str>,
) -> Result<FiniteSourceSelection, InventoryParseError> {
    let text = std::str::from_utf8(bytes).map_err(|_| InventoryParseError)?;
    let value: toml::Value = toml::from_str(text).map_err(|_| InventoryParseError)?;
    let base = value.as_table().ok_or(InventoryParseError)?;
    let selected_name = selected_profile(bytes, profile)?;
    let selected = selected_name
        .as_deref()
        .map(|name| {
            base.get("profiles")
                .and_then(|value| value.get(name))
                .and_then(toml::Value::as_table)
                .ok_or(InventoryParseError)
        })
        .transpose()?;
    // Only the supported profile file selector is resolved here. Other source
    // selectors in a profile cannot certify the base layer's positive result.
    let get = |key: &str| {
        (key == "model_instructions_file")
            .then(|| selected.and_then(|value| value.get(key)))
            .flatten()
            .or_else(|| base.get(key))
    };
    let names = |key: &str, default: Vec<String>| -> Result<Vec<String>, InventoryParseError> {
        get(key).map_or(Ok(default), |value| {
            let names = value
                .as_array()
                .ok_or(InventoryParseError)?
                .iter()
                .map(|value| {
                    let name = value.as_str().ok_or(InventoryParseError)?;
                    if name.is_empty()
                        || name.len() > 255
                        || name.contains(['/', '\\'])
                        || name == "."
                        || name == ".."
                        || name.chars().any(char::is_control)
                    {
                        return Err(InventoryParseError);
                    }
                    Ok(name.to_owned())
                })
                .collect::<Result<Vec<_>, _>>()?;
            if names.len() > 32 {
                return Err(InventoryParseError);
            }
            Ok(names)
        })
    };
    let mut enabled_plugins = BTreeMap::new();
    if let Some(plugins) = get("plugins") {
        for (id, plugin) in plugins.as_table().ok_or(InventoryParseError)? {
            let (name, marketplace) = id.split_once('@').ok_or(InventoryParseError)?;
            if !safe_component(name) || !safe_component(marketplace) {
                return Err(InventoryParseError);
            }
            let enabled = plugin
                .as_table()
                .ok_or(InventoryParseError)?
                .get("enabled")
                .map(|value| value.as_bool().ok_or(InventoryParseError))
                .transpose()?
                .unwrap_or(true);
            enabled_plugins.insert(id.clone(), enabled);
        }
    }
    let mut skill_rules = Vec::new();
    let mut observed = selected.is_none_or(|table| {
        ![
            "plugins",
            "skills",
            "features",
            "project_doc_max_bytes",
            "project_root_markers",
            "project_doc_fallback_filenames",
            "developer_instructions",
            "instructions",
            "skill_roots",
        ]
        .iter()
        .any(|key| table.contains_key(*key))
    });
    if let Some(skills) = get("skills") {
        let skills = skills.as_table().ok_or(InventoryParseError)?;
        if skills.keys().any(|key| key != "config") {
            observed = false;
        }
        if let Some(rules) = skills.get("config") {
            for rule in rules.as_array().ok_or(InventoryParseError)? {
                let enabled = rule
                    .get("enabled")
                    .and_then(toml::Value::as_bool)
                    .ok_or(InventoryParseError)?;
                let path = rule
                    .get("path")
                    .map(|value| value.as_str().ok_or(InventoryParseError))
                    .transpose()?;
                let name = rule
                    .get("name")
                    .map(|value| value.as_str().ok_or(InventoryParseError))
                    .transpose()?;
                let selector = match (path, name) {
                    (Some(path), None) => {
                        if !crate::binding::valid_lexical_absolute_path(path) {
                            return Err(InventoryParseError);
                        }
                        // Host canonicalizes path selectors. The scanner uses
                        // confined canonical files; unresolved aliases are not guessed.
                        SkillSelector::Path(PathBuf::from(path))
                    }
                    (None, Some(name)) if !name.trim().is_empty() => {
                        SkillSelector::Name(name.trim().to_owned())
                    }
                    _ => continue, // Host ignores ambiguous/empty selectors.
                };
                skill_rules.retain(|rule: &SkillSelectionRule| rule.selector != selector);
                skill_rules.push(SkillSelectionRule { selector, enabled });
            }
        }
    }
    let user_instruction_file = get("model_instructions_file")
        .map(|value| {
            let path = value.as_str().ok_or(InventoryParseError)?;
            if !crate::binding::valid_lexical_absolute_path(path) {
                return Err(InventoryParseError);
            }
            Ok(PathBuf::from(path))
        })
        .transpose()?;
    if get("developer_instructions").is_some()
        || get("instructions").is_some()
        || get("skill_roots").is_some()
    {
        observed = false;
    }
    Ok(FiniteSourceSelection {
        instruction_fallback_names: names("project_doc_fallback_filenames", Vec::new())?,
        root_markers: names("project_root_markers", vec![".git".into()])?,
        user_instruction_file,
        enabled_plugins,
        plugins_enabled: base
            .get("features")
            .map(|value| value.as_table().ok_or(InventoryParseError))
            .transpose()?
            .and_then(|table| table.get("plugins"))
            .map(|value| value.as_bool().ok_or(InventoryParseError))
            .transpose()?
            .unwrap_or(true),
        project_doc_max_bytes: get("project_doc_max_bytes")
            .map(|value| {
                value
                    .as_integer()
                    .and_then(|number| number.try_into().ok())
                    .ok_or(InventoryParseError)
            })
            .transpose()?
            .unwrap_or(32 * 1024),
        skill_rules,
        source_overrides_present: [
            "project_doc_max_bytes",
            "project_doc_fallback_filenames",
            "project_root_markers",
            "model_instructions_file",
            "plugins",
            "skills",
            "skill_roots",
            "instructions",
            "developer_instructions",
            "profile",
        ]
        .iter()
        .any(|key| base.contains_key(*key))
            || base
                .get("features")
                .and_then(|value| value.get("plugins"))
                .is_some(),
        observed,
    })
}

// Validate the fixed legacy manifest's typed envelope, including duplicate
// known fields. Other contribution bodies accept the Host's catch-all shapes;
// this parser neither resolves nor executes those contributions.
#[derive(Deserialize)]
struct LocalPluginManifest {
    #[serde(default, rename = "name")]
    _name: String,
    #[serde(rename = "version")]
    _version: Option<String>,
    #[serde(rename = "description")]
    _description: Option<String>,
    #[serde(default, rename = "keywords")]
    _keywords: Vec<String>,
    skills: Option<serde_json::Value>,
    #[serde(rename = "mcpServers")]
    _mcp_servers: Option<serde_json::Value>,
    #[serde(rename = "apps")]
    _apps: Option<String>,
    #[serde(rename = "hooks")]
    _hooks: Option<serde_json::Value>,
    #[serde(rename = "interface")]
    _interface: Option<LocalPluginInterface>,
}

#[derive(Deserialize)]
struct LocalPluginInterface {
    #[serde(rename = "displayName")]
    _display_name: Option<String>,
    #[serde(rename = "shortDescription")]
    _short_description: Option<String>,
    #[serde(rename = "longDescription")]
    _long_description: Option<String>,
    #[serde(rename = "developerName")]
    _developer_name: Option<String>,
    #[serde(rename = "category")]
    _category: Option<String>,
    #[serde(default, rename = "capabilities")]
    _capabilities: Vec<String>,
    #[serde(rename = "websiteUrl", alias = "websiteURL")]
    _website_url: Option<String>,
    #[serde(rename = "privacyPolicyUrl", alias = "privacyPolicyURL")]
    _privacy_policy_url: Option<String>,
    #[serde(rename = "termsOfServiceUrl", alias = "termsOfServiceURL")]
    _terms_of_service_url: Option<String>,
    #[serde(rename = "defaultPrompt")]
    _default_prompt: Option<serde_json::Value>,
    #[serde(rename = "brandColor")]
    _brand_color: Option<String>,
    #[serde(rename = "composerIcon")]
    _composer_icon: Option<String>,
    #[serde(rename = "logo")]
    _logo: Option<String>,
    #[serde(rename = "logoDark")]
    _logo_dark: Option<String>,
    #[serde(default, rename = "screenshots")]
    _screenshots: Vec<String>,
}

pub fn plugin_skill_paths(bytes: &[u8], root: &Path) -> Result<Vec<PathBuf>, InventoryAssetError> {
    use InventoryAssetError::{Invalid, Unsupported};
    let manifest: LocalPluginManifest = serde_json::from_slice(bytes).map_err(|_| Invalid)?;
    let Some(paths) = manifest.skills else {
        return Ok(vec![root.join("skills")]);
    };
    let values = if let Some(path) = paths.as_str() {
        vec![path]
    } else {
        paths
            .as_array()
            .ok_or(Unsupported)?
            .iter()
            .map(|value| value.as_str().ok_or(Unsupported))
            .collect::<Result<Vec<_>, _>>()?
    };
    if values.is_empty() {
        return Ok(vec![root.join("skills")]);
    }
    let mut paths = values
        .into_iter()
        .map(|value| {
            let relative = value.strip_prefix("./").ok_or(Unsupported)?;
            if relative.is_empty()
                || Path::new(relative)
                    .components()
                    .any(|part| !matches!(part, std::path::Component::Normal(_)))
            {
                return Err(Unsupported);
            }
            Ok(root.join(relative))
        })
        .collect::<Result<Vec<_>, _>>()?;
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

pub fn is_agent_plugin_manifest(bytes: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|value| {
            value
                .get("$schema")
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned)
        })
        .is_some_and(|schema| schema.starts_with("https://agent-plugins.org/schemas/"))
}

/// Recognizes a closed scalar-only subset, not general YAML. Unsupported
/// syntax cannot certify that the fixed Host would load the document.
pub fn authored_skill_fields(
    bytes: &[u8],
    fallback_name: &str,
) -> Result<(String, String), InventoryAssetError> {
    use InventoryAssetError::{Invalid, Unsupported};
    let text = std::str::from_utf8(bytes).map_err(|_| Invalid)?;
    let mut lines = text.lines();
    if !lines.next().is_some_and(|line| line.trim() == "---") {
        return Err(Invalid);
    }
    let mut fields = BTreeMap::new();
    let mut closed = false;
    for line in lines {
        if line.trim() == "---" {
            closed = true;
            break;
        }
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        if line.starts_with(char::is_whitespace) {
            return Err(Unsupported);
        }
        let (key, value) = line.split_once(':').ok_or(Unsupported)?;
        if !key
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || *byte == b'_')
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
        {
            return Err(Unsupported);
        }
        if !value.starts_with(char::is_whitespace) && !value.is_empty() {
            return Err(Unsupported);
        }
        let value = value.trim();
        let scalar = if value.starts_with('"') {
            Some(serde_json::from_str::<String>(value).map_err(|_| Unsupported)?)
        } else if matches!(value, "" | "null" | "Null" | "NULL" | "~") {
            if !matches!(key, "name" | "description") {
                return Err(Unsupported);
            }
            // Retain null entries so duplicate fields are still rejected.
            None
        } else {
            if value.chars().any(|c| "#[]{}&*!|>'\"%@`".contains(c))
                || value.contains(": ")
                || value.starts_with(['-', '?', ':'])
                || matches!(value, "true" | "false" | "yes" | "no")
                || value.parse::<f64>().is_ok()
            {
                return Err(Unsupported);
            }
            Some(value.to_owned())
        };
        if fields.insert(key, scalar).is_some() {
            return Err(if matches!(key, "name" | "description") {
                Invalid
            } else {
                Unsupported
            });
        }
    }
    if !closed || fields.is_empty() {
        return Err(Invalid);
    }
    // The Host expects a typed metadata map; scalar-only support must not
    // accidentally admit an invalid metadata value just because it is unused.
    if fields.contains_key("metadata") {
        return Err(Unsupported);
    }
    let clean = |value: &str| value.split_whitespace().collect::<Vec<_>>().join(" ");
    let name = fields
        .get("name")
        .and_then(|value| value.as_deref())
        .map(clean)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| fallback_name.to_owned());
    let description = fields
        .get("description")
        .and_then(|value| value.as_deref())
        .map(clean)
        .ok_or(Invalid)?;
    if name.is_empty() || name.chars().count() > 64 || description.is_empty() {
        return Err(Invalid);
    }
    Ok((name, description))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finite_selection_keeps_enable_scope_and_unknown_structure_separate() {
        let selected = source_selection(
            br#"
            api_key = "unrelated-secret"
            [plugins."local@private"]
            enabled = true
            [plugins."off@private"]
            enabled = false
            [[skills.config]]
            path = "/actual/skill/SKILL.md"
            enabled = false
        "#,
            None,
        )
        .unwrap();
        assert_eq!(selected.enabled_plugins.get("local@private"), Some(&true));
        assert_eq!(selected.enabled_plugins.get("off@private"), Some(&false));
        assert!(!selected.skill_enabled(Path::new("/actual/skill/SKILL.md"), "example"));
        assert!(selected.observed);
        assert!(!format!("{selected:?}").contains("unrelated-secret"));
        assert!(
            !source_selection(b"[skills]\nextra_roots = ['/elsewhere']", None)
                .unwrap()
                .observed
        );
        assert!(source_selection(b"", Some("missing")).is_err());
        assert!(plugin_skill_paths(br#"{"skills":"./../outside"}"#, Path::new("/plugin")).is_err());
        assert_eq!(
            plugin_skill_paths(br#"{"skills":["./skills"]}"#, Path::new("/plugin")).unwrap(),
            [PathBuf::from("/plugin/skills")]
        );
    }

    #[test]
    fn finite_selection_applies_defaults_byte_gate_and_ordered_names() {
        let selected = source_selection(
            br#"
project_doc_max_bytes = 0
[plugins."default@private"]
[features]
plugins = false
[[skills.config]]
path = "/actual/skill/SKILL.md"
enabled = false
[[skills.config]]
name = " example "
enabled = true
[[skills.config]]
path = "/actual/skill/SKILL.md"
enabled = false
"#,
            None,
        )
        .unwrap();
        assert!(selected.observed);
        assert_eq!(selected.enabled_plugins.get("default@private"), Some(&true));
        assert!(!selected.plugins_enabled);
        assert_eq!(selected.project_doc_max_bytes, 0);
        assert!(!selected.skill_enabled(Path::new("/actual/skill/SKILL.md"), "example"));
        assert!(selected.skill_enabled(Path::new("/another/SKILL.md"), "example"));
        let defaults = source_selection(b"", None).unwrap();
        assert!(defaults.plugins_enabled && defaults.observed);
        assert_eq!(defaults.project_doc_max_bytes, 32 * 1024);
        assert!(
            !source_selection(
                b"profile = 'work'\n[profiles.work.features]\nplugins = false",
                None
            )
            .unwrap()
            .observed
        );
        assert!(
            source_selection(b"project_doc_max_bytes = 32768", None)
                .unwrap()
                .source_overrides_present
        );
        assert!(source_selection(b"project_doc_max_bytes = -1", None).is_err());
    }

    #[test]
    fn finite_assets_require_host_load_validity_before_authored_fields() {
        assert_eq!(
            plugin_skill_paths(br#"{"name":7}"#, Path::new("/plugin")),
            Err(InventoryAssetError::Invalid)
        );
        assert_eq!(
            plugin_skill_paths(br#"{"name":7,"name":"later"}"#, Path::new("/plugin")),
            Err(InventoryAssetError::Invalid)
        );
        assert_eq!(
            plugin_skill_paths(br#"{"interface":{"displayName":7}}"#, Path::new("/plugin")),
            Err(InventoryAssetError::Invalid)
        );
        assert!(
            plugin_skill_paths(
                br#"{"interface":{"displayName":"local","defaultPrompt":["run"]}}"#,
                Path::new("/plugin")
            )
            .is_ok()
        );
        assert_eq!(
            plugin_skill_paths(br#"{"keywords":[7]}"#, Path::new("/plugin")),
            Err(InventoryAssetError::Invalid)
        );
        assert_eq!(
            plugin_skill_paths(br#"{}"#, Path::new("/plugin")).unwrap(),
            [PathBuf::from("/plugin/skills")]
        );
        assert_eq!(
            authored_skill_fields(b"no frontmatter", "fallback"),
            Err(InventoryAssetError::Invalid)
        );
        assert_eq!(
            authored_skill_fields(b"---\nname: example\n---\n", "fallback"),
            Err(InventoryAssetError::Invalid)
        );
        assert_eq!(
            authored_skill_fields(
                b"---\nname: example\nbroken yaml\ndescription: test\n---\n",
                "fallback"
            ),
            Err(InventoryAssetError::Unsupported)
        );
        assert_eq!(
            authored_skill_fields(b"---\ndescription: |\n  complex\n---\n", "fallback"),
            Err(InventoryAssetError::Unsupported)
        );
        assert_eq!(
            authored_skill_fields(
                b" --- \r\ndescription:  bounded   authored text\r\n---\r\nbody",
                "fallback"
            )
            .unwrap(),
            ("fallback".into(), "bounded authored text".into())
        );
        assert_eq!(
            authored_skill_fields(
                b"---\nname: \"  \"\ndescription: \"a\\nb\"\n---\n",
                "fallback"
            )
            .unwrap(),
            ("fallback".into(), "a b".into())
        );
    }

    #[test]
    fn finite_skill_null_fields_keep_fallback_and_duplicate_rules() {
        for null in ["", "null", "Null", "NULL", "~"] {
            assert_eq!(
                authored_skill_fields(
                    format!("---\nname: {null}\ndescription: authored text\n---\n").as_bytes(),
                    "fallback"
                ),
                Ok(("fallback".into(), "authored text".into()))
            );
            assert_eq!(
                authored_skill_fields(
                    format!("---\ndescription: {null}\n---\n").as_bytes(),
                    "fallback"
                ),
                Err(InventoryAssetError::Invalid)
            );
        }
        assert_eq!(
            authored_skill_fields(
                b"---\nname: \"Null\"\ndescription: \"Null\"\n---\n",
                "fallback"
            ),
            Ok(("Null".into(), "Null".into()))
        );
        assert_eq!(
            authored_skill_fields(
                b"---\nname: Null\nname: replacement\ndescription: authored text\n---\n",
                "fallback"
            ),
            Err(InventoryAssetError::Invalid)
        );
        assert_eq!(
            authored_skill_fields(
                b"---\ndescription: Null\ndescription: replacement\n---\n",
                "fallback"
            ),
            Err(InventoryAssetError::Invalid)
        );
    }
}
