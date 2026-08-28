use std::path::PathBuf;

pub(super) fn strict_patch_target(patch: &[u8]) -> Option<PathBuf> {
    let text = std::str::from_utf8(patch).ok()?;
    let mut target = None::<&str>;
    let mut old_header = None::<&str>;
    let mut new_header = None::<&str>;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("diff --git a/") {
            let (left, right) = value.split_once(" b/")?;
            if target.replace(left).is_some() || left != right {
                return None;
            }
        } else if let Some(value) = line.strip_prefix("--- a/") {
            if old_header.replace(value).is_some() {
                return None;
            }
        } else if let Some(value) = line.strip_prefix("+++ b/") {
            if new_header.replace(value).is_some() {
                return None;
            }
        } else if line.starts_with("--- ")
            || line.starts_with("+++ ")
            || line.starts_with("rename from ")
            || line.starts_with("rename to ")
            || line.starts_with("copy from ")
            || line.starts_with("copy to ")
            || line.starts_with("new file mode ")
            || line.starts_with("deleted file mode ")
            || line.starts_with("GIT binary patch")
            || line.starts_with("Binary files ")
        {
            return None;
        }
    }
    let target = target?;
    if old_header != Some(target)
        || new_header != Some(target)
        || target.is_empty()
        || target.len() > 4096
        || !target
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'-' | b'.'))
    {
        return None;
    }
    let path = PathBuf::from(target);
    path.components()
        .all(
            |component| matches!(component, std::path::Component::Normal(value) if value != ".git"),
        )
        .then_some(path)
}

#[cfg(test)]
mod tests {
    use super::strict_patch_target;

    fn patch(path: &str) -> Vec<u8> {
        format!(
            "diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n"
        )
        .into_bytes()
    }

    #[test]
    fn strict_target_rejects_git_admin_at_any_depth() {
        assert_eq!(
            strict_patch_target(&patch("tracked.txt")).unwrap(),
            std::path::PathBuf::from("tracked.txt")
        );
        assert!(strict_patch_target(&patch(".git/config")).is_none());
        assert!(strict_patch_target(&patch("sub/.git/config")).is_none());
    }
}
