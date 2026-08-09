//! Unified diff → structured lines, for calm rendering.

pub struct FileDiff {
    pub path: String,
    pub hunks: Vec<Hunk>,
}

pub struct Hunk {
    pub header: String,
    pub lines: Vec<Line>,
}

pub struct Line {
    pub kind: LineKind,
    /// New-file line number; deletions carry the old-file number.
    pub number: i64,
    pub text: String,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LineKind {
    Context,
    Add,
    Del,
}

/// Parse `git show --patch` output. Tolerant: anything unrecognized
/// between files (index lines, mode changes, binary notices) is
/// skipped rather than guessed at.
pub fn parse(patch: &str) -> Vec<FileDiff> {
    let mut files: Vec<FileDiff> = Vec::new();
    let mut old_no = 0i64;
    let mut new_no = 0i64;
    for line in patch.lines() {
        if line.starts_with("diff --git ") {
            files.push(FileDiff {
                path: String::new(),
                hunks: Vec::new(),
            });
        } else if let Some(path) = line.strip_prefix("+++ b/") {
            if let Some(file) = files.last_mut() {
                file.path = path.to_owned();
            }
        } else if let Some(path) = line.strip_prefix("--- a/") {
            // Keeps a name for deleted files, where no +++ b/ follows.
            if let Some(file) = files.last_mut()
                && file.path.is_empty()
            {
                file.path = path.to_owned();
            }
        } else if line.starts_with("@@ ") {
            let (old_start, new_start) = parse_hunk_header(line);
            old_no = old_start;
            new_no = new_start;
            if let Some(file) = files.last_mut() {
                file.hunks.push(Hunk {
                    header: line.to_owned(),
                    lines: Vec::new(),
                });
            }
        } else if let Some(hunk) = files.last_mut().and_then(|f| f.hunks.last_mut()) {
            let (kind, number, text) = match line.split_at_checked(1) {
                Some(("+", rest)) => {
                    let n = new_no;
                    new_no += 1;
                    (LineKind::Add, n, rest)
                }
                Some(("-", rest)) => {
                    let n = old_no;
                    old_no += 1;
                    (LineKind::Del, n, rest)
                }
                Some((" ", rest)) => {
                    let n = new_no;
                    old_no += 1;
                    new_no += 1;
                    (LineKind::Context, n, rest)
                }
                _ => continue,
            };
            hunk.lines.push(Line {
                kind,
                number,
                text: text.to_owned(),
            });
        }
    }
    files.retain(|f| !f.hunks.is_empty());
    files
}

fn parse_hunk_header(header: &str) -> (i64, i64) {
    // "@@ -old[,n] +new[,n] @@ ..."
    let mut old_start = 1;
    let mut new_start = 1;
    for part in header.split(' ') {
        if let Some(rest) = part.strip_prefix('-') {
            old_start = rest
                .split(',')
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(1);
        } else if let Some(rest) = part.strip_prefix('+') {
            new_start = rest
                .split(',')
                .next()
                .and_then(|n| n.parse().ok())
                .unwrap_or(1);
        }
    }
    (old_start, new_start)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PATCH: &str = "\
diff --git a/src/id.rs b/src/id.rs
index 1111111..2222222 100644
--- a/src/id.rs
+++ b/src/id.rs
@@ -18,3 +18,4 @@ fn validate
 let ok = true;
-(2..=64).contains(&len)
+(2..=64).contains(&len)
+    && !s.starts_with('-')
";

    #[test]
    fn parses_paths_hunks_and_numbers() {
        let files = parse(PATCH);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].path, "src/id.rs");
        let lines = &files[0].hunks[0].lines;
        assert_eq!(lines.len(), 4);
        assert_eq!(lines[0].kind, LineKind::Context);
        assert_eq!(lines[0].number, 18);
        assert_eq!(lines[1].kind, LineKind::Del);
        assert_eq!(lines[2].kind, LineKind::Add);
        assert_eq!(lines[2].number, 19);
        assert_eq!(lines[3].number, 20);
        assert_eq!(lines[3].text, "    && !s.starts_with('-')");
    }

    #[test]
    fn empty_and_garbage_inputs_parse_to_nothing() {
        assert!(parse("").is_empty());
        assert!(parse("not a diff at all\njust text\n").is_empty());
    }
}
