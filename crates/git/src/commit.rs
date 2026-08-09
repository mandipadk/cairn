//! Parsing raw commit objects, as printed by `git cat-file commit`.

/// What the forge needs to know about a pushed commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitInfo {
    /// First line of the message.
    pub title: String,
    /// Full message, headers excluded.
    pub message: String,
    /// The `Change-Id:` trailer, if present — the stable key that lets
    /// an amended commit address the same change.
    pub change_id: Option<String>,
}

pub fn parse_commit_object(raw: &str) -> CommitInfo {
    // Headers run until the first blank line; the rest is the message.
    let message = match raw.split_once("\n\n") {
        Some((_headers, message)) => message.trim_end().to_owned(),
        None => String::new(),
    };
    let title = message.lines().next().unwrap_or("").to_owned();
    let change_id = message
        .lines()
        .rev()
        .find_map(|line| line.strip_prefix("Change-Id:"))
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    CommitInfo {
        title,
        message,
        change_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW: &str = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
                       author Ada <ada@example.test> 1700000000 +0000\n\
                       committer Ada <ada@example.test> 1700000000 +0000\n\
                       \n\
                       Add greeting\n\
                       \n\
                       Longer explanation of why.\n\
                       \n\
                       Change-Id: If00dcafe\n";

    #[test]
    fn parses_title_message_and_trailer() {
        let info = parse_commit_object(RAW);
        assert_eq!(info.title, "Add greeting");
        assert!(info.message.starts_with("Add greeting"));
        assert!(info.message.ends_with("Change-Id: If00dcafe"));
        assert_eq!(info.change_id.as_deref(), Some("If00dcafe"));
    }

    #[test]
    fn missing_trailer_is_none() {
        let info = parse_commit_object("tree x\n\nJust a title\n");
        assert_eq!(info.title, "Just a title");
        assert_eq!(info.change_id, None);
    }

    #[test]
    fn empty_trailer_value_is_none() {
        let info = parse_commit_object("tree x\n\nTitle\n\nChange-Id:\n");
        assert_eq!(info.change_id, None);
    }
}
