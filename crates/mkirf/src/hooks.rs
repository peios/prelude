//! Hook DAG — discover initramfs hooks, parse their co-located metadata,
//! and resolve a deterministic execution order.
//!
//! A hook is a regular file directly under `<src>/hooks/`. prelude runs
//! hooks, in the order resolved here, inside the initramfs before
//! switch_root. Each hook declares its ordering in a fenced comment block
//! (PEP 723-style); mkirf topologically sorts the resulting capability
//! DAG and bakes the order into `hooks.seq`. See boot-design.md §3.6.

use std::collections::{BTreeSet, HashMap};
use std::error::Error;
use std::fs;
use std::path::Path;

/// `hooks.seq` format-version marker — the file's first line.
pub const SEQ_VERSION_LINE: &str = "hookseq 1";

/// One discovered hook and its parsed ordering metadata.
#[derive(Debug)]
pub struct Hook {
    /// File name within `hooks/`, e.g. `"luks-unlock.sh"`.
    pub name: String,
    /// Capabilities this hook satisfies.
    pub provides: Vec<String>,
    /// Capabilities that must be satisfied before this hook runs.
    pub requires: Vec<String>,
    /// Whether the hook carried a `# /// hook` metadata block at all.
    /// A hook with no block is the escape hatch (§3.6): valid, but
    /// scheduled last and warned about.
    pub has_block: bool,
}

/// The resolved hook execution order plus any build-time advisories.
#[derive(Debug)]
pub struct Resolved {
    /// `hooks.seq` lines after the version marker: cpio-absolute hook
    /// paths, in execution order.
    pub order: Vec<String>,
    /// Non-fatal advisories for the caller to print.
    pub warnings: Vec<String>,
}

/// Discover and parse every hook under `hooks_dir`.
///
/// Every regular file directly in the directory is a hook; the directory
/// is not searched recursively. Anything that is not a regular file (a
/// subdirectory, say) is left to the walker and not treated as a hook.
/// The returned hooks are sorted by name.
pub fn discover(hooks_dir: &Path) -> Result<Vec<Hook>, Box<dyn Error>> {
    let mut hooks = Vec::new();
    for entry in fs::read_dir(hooks_dir).map_err(|e| format!("{}: {e}", hooks_dir.display()))? {
        let entry = entry.map_err(|e| format!("{}: {e}", hooks_dir.display()))?;
        let path = entry.path();
        // fs::metadata follows symlinks, so a symlinked hook is judged by
        // its target's type.
        let meta = fs::metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        if !meta.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let text = fs::read_to_string(&path).map_err(|e| format!("hook `{name}`: {e}"))?;
        let parsed = parse_block(&text).map_err(|e| format!("hook `{name}`: {e}"))?;
        hooks.push(Hook {
            name,
            provides: parsed.provides,
            requires: parsed.requires,
            has_block: parsed.has_block,
        });
    }
    hooks.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    Ok(hooks)
}

/// The metadata extracted from a single hook script.
#[derive(Debug)]
struct Parsed {
    provides: Vec<String>,
    requires: Vec<String>,
    has_block: bool,
}

/// Extract a hook's ordering metadata from its script text.
///
/// The metadata is a fenced comment block: a line `# /// hook`, then
/// `#`-prefixed lines, then a closing `# ///`. Each content line with its
/// `# ` prefix removed is a small TOML subset — top-level
/// `key = ["string", ...]` assignments. A hook with no block is valid
/// (`has_block = false`); a malformed block is an error.
fn parse_block(text: &str) -> Result<Parsed, String> {
    let lines: Vec<&str> = text.lines().collect();

    let Some(open) = lines.iter().position(|l| l.trim_end() == "# /// hook") else {
        // No block at all — the escape hatch.
        return Ok(Parsed { provides: Vec::new(), requires: Vec::new(), has_block: false });
    };
    if lines[open + 1..].iter().any(|l| l.trim_end() == "# /// hook") {
        return Err("more than one `# /// hook` metadata block".into());
    }

    let mut content: Vec<(usize, String)> = Vec::new();
    let mut closed = false;
    for (i, line) in lines.iter().enumerate().skip(open + 1) {
        if line.trim_end() == "# ///" {
            closed = true;
            break;
        }
        // Every line within the block must be a comment line: `# ` then
        // content, or a bare `#`.
        let body = if let Some(rest) = line.strip_prefix("# ") {
            rest.to_string()
        } else if line.trim_end() == "#" {
            String::new()
        } else {
            return Err(format!(
                "line {}: content inside the metadata block must be `# `-prefixed",
                i + 1,
            ));
        };
        content.push((i + 1, body));
    }
    if !closed {
        return Err("`# /// hook` block is never closed with `# ///`".into());
    }

    let (provides, requires) = parse_toml_subset(&content)?;
    Ok(Parsed { provides, requires, has_block: true })
}

/// Parse the metadata block's content — the TOML subset mkirf accepts:
/// blank lines, `#` comments, and top-level `key = ["str", ...]`
/// assignments where `key` is `provides` or `requires`.
fn parse_toml_subset(content: &[(usize, String)]) -> Result<(Vec<String>, Vec<String>), String> {
    let mut provides: Option<Vec<String>> = None;
    let mut requires: Option<Vec<String>> = None;

    for (lineno, raw) in content {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("line {lineno}: expected `key = [...]`"))?;
        let slot = match key.trim() {
            "provides" => &mut provides,
            "requires" => &mut requires,
            other => {
                return Err(format!(
                    "line {lineno}: unknown key `{other}` (expected `provides` or `requires`)"
                ))
            }
        };
        if slot.is_some() {
            return Err(format!("line {lineno}: duplicate key `{}`", key.trim()));
        }
        *slot = Some(parse_string_array(value.trim()).map_err(|e| format!("line {lineno}: {e}"))?);
    }

    Ok((provides.unwrap_or_default(), requires.unwrap_or_default()))
}

/// Parse a TOML inline array of double-quoted strings: `["a", "b"]`.
/// Deliberately strict — capability names are simple tokens, so no escape
/// handling is needed and anything fancier is rejected.
fn parse_string_array(s: &str) -> Result<Vec<String>, String> {
    let inner = s
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or_else(|| format!("expected an array `[...]`, found `{s}`"))?
        .trim();
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut elems: Vec<&str> = inner.split(',').map(str::trim).collect();
    if elems.last() == Some(&"") {
        elems.pop(); // a single trailing comma is permitted, as in TOML
    }
    let mut out = Vec::new();
    for elem in elems {
        if elem.is_empty() {
            return Err("empty array element (doubled comma?)".into());
        }
        let value = elem
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .ok_or_else(|| format!("array element `{elem}` is not a double-quoted string"))?;
        if value.is_empty() {
            return Err("empty capability name".into());
        }
        if value.contains('"') {
            return Err(format!("array element `{elem}` contains an embedded quote"));
        }
        out.push(value.to_string());
    }
    Ok(out)
}

/// Topologically sort `hooks` into an execution order.
///
/// Constrained hooks — those declaring any `provides`/`requires` — are
/// ordered by their capability DAG: Kahn's algorithm, ties broken by file
/// name in `LC_ALL=C` byte order. Unconstrained hooks (both lists empty,
/// block present or not) run afterwards in name order. A dependency
/// cycle, or a `requires` no hook satisfies, is an error.
pub fn resolve(hooks: &[Hook]) -> Result<Resolved, String> {
    // Work from a name-sorted view so the result does not depend on the
    // order `discover` happened to return.
    let mut sorted: Vec<&Hook> = hooks.iter().collect();
    sorted.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));

    let (constrained, unconstrained): (Vec<&Hook>, Vec<&Hook>) = sorted
        .into_iter()
        .partition(|h| !h.provides.is_empty() || !h.requires.is_empty());

    // Every required capability must be provided by some hook.
    let all_provides: BTreeSet<&str> = hooks
        .iter()
        .flat_map(|h| h.provides.iter().map(String::as_str))
        .collect();
    for h in &constrained {
        for req in &h.requires {
            if !all_provides.contains(req.as_str()) {
                return Err(format!(
                    "hook `{}` requires capability `{}`, which no hook provides",
                    h.name, req,
                ));
            }
        }
    }

    let order = kahn_sort(&constrained)?;

    let mut paths: Vec<String> = order
        .iter()
        .map(|&i| format!("/hooks/{}", constrained[i].name))
        .collect();
    paths.extend(unconstrained.iter().map(|h| format!("/hooks/{}", h.name)));

    // Unconstrained hooks with no block at all get an advisory: a
    // forgotten block looks identical to a deliberate one, so make it
    // visible (§3.6).
    let warnings: Vec<String> = unconstrained
        .iter()
        .filter(|h| !h.has_block)
        .map(|h| {
            format!(
                "hook `{}` has no `# /// hook` metadata block; scheduling it last",
                h.name,
            )
        })
        .collect();

    Ok(Resolved { order: paths, warnings })
}

/// Kahn's algorithm over the constrained hooks. Returns indices into
/// `constrained` in execution order, or an error naming the hooks caught
/// in a dependency cycle.
fn kahn_sort(constrained: &[&Hook]) -> Result<Vec<usize>, String> {
    let n = constrained.len();

    // capability -> indices of constrained hooks that provide it.
    let mut providers: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, h) in constrained.iter().enumerate() {
        for cap in &h.provides {
            providers.entry(cap.as_str()).or_default().push(i);
        }
    }

    // Edges p -> c: provider p must run before consumer c. A BTreeSet
    // dedups (a provider supplying two capabilities one hook needs) and
    // keeps iteration deterministic.
    let mut edge_set: BTreeSet<(usize, usize)> = BTreeSet::new();
    for (c, h) in constrained.iter().enumerate() {
        for req in &h.requires {
            for &p in providers.get(req.as_str()).into_iter().flatten() {
                if p != c {
                    edge_set.insert((p, c));
                }
            }
        }
    }
    let mut edges: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut indegree: Vec<usize> = vec![0; n];
    for &(p, c) in &edge_set {
        edges[p].push(c);
        indegree[c] += 1;
    }

    // `constrained` is name-sorted, so the smallest ready index is the
    // lexicographically-smallest hook name — that is the tie-break.
    let mut ready: BTreeSet<usize> = (0..n).filter(|&i| indegree[i] == 0).collect();
    let mut order = Vec::with_capacity(n);
    while let Some(node) = ready.pop_first() {
        order.push(node);
        for &succ in &edges[node] {
            indegree[succ] -= 1;
            if indegree[succ] == 0 {
                ready.insert(succ);
            }
        }
    }

    if order.len() != n {
        let mut placed = vec![false; n];
        for &i in &order {
            placed[i] = true;
        }
        let stuck: Vec<&str> = (0..n)
            .filter(|&i| !placed[i])
            .map(|i| constrained[i].name.as_str())
            .collect();
        return Err(format!("hook dependency cycle involving: {}", stuck.join(", ")));
    }
    Ok(order)
}

/// Render the `hooks.seq` file body from a resolved order.
pub fn render_seq(order: &[String]) -> Vec<u8> {
    let mut s = String::from(SEQ_VERSION_LINE);
    s.push('\n');
    for path in order {
        s.push_str(path);
        s.push('\n');
    }
    s.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Build a hook with a metadata block present.
    fn hook(name: &str, provides: &[&str], requires: &[&str]) -> Hook {
        Hook {
            name: name.to_string(),
            provides: provides.iter().map(|s| s.to_string()).collect(),
            requires: requires.iter().map(|s| s.to_string()).collect(),
            has_block: true,
        }
    }

    // --- parse_block -----------------------------------------------------

    #[test]
    fn no_block_is_the_escape_hatch() {
        let p = parse_block("#!/bin/sh\necho hi\n").unwrap();
        assert!(!p.has_block);
        assert!(p.provides.is_empty() && p.requires.is_empty());
    }

    #[test]
    fn valid_block_is_parsed() {
        let text = "#!/bin/sh\n\
                     # /// hook\n\
                     # provides = [\"crypto-unlocked\"]\n\
                     # requires = [\"modules-loaded\", \"udev-settled\"]\n\
                     # ///\n\
                     echo body\n";
        let p = parse_block(text).unwrap();
        assert!(p.has_block);
        assert_eq!(p.provides, ["crypto-unlocked"]);
        assert_eq!(p.requires, ["modules-loaded", "udev-settled"]);
    }

    #[test]
    fn empty_block_is_constraint_free_but_present() {
        let p = parse_block("#!/bin/sh\n# /// hook\n# ///\n").unwrap();
        assert!(p.has_block);
        assert!(p.provides.is_empty() && p.requires.is_empty());
    }

    #[test]
    fn unclosed_block_is_an_error() {
        let err = parse_block("# /// hook\n# provides = [\"x\"]\n").unwrap_err();
        assert!(err.contains("never closed"), "{err}");
    }

    #[test]
    fn non_comment_line_in_block_is_an_error() {
        let err = parse_block("# /// hook\nprovides = [\"x\"]\n# ///\n").unwrap_err();
        assert!(err.contains("`# `-prefixed"), "{err}");
    }

    #[test]
    fn second_block_is_an_error() {
        let text = "# /// hook\n# ///\n# /// hook\n# ///\n";
        assert!(parse_block(text).unwrap_err().contains("more than one"));
    }

    #[test]
    fn unknown_key_is_an_error() {
        let err = parse_block("# /// hook\n# requirez = [\"x\"]\n# ///\n").unwrap_err();
        assert!(err.contains("unknown key"), "{err}");
    }

    #[test]
    fn duplicate_key_is_an_error() {
        let text = "# /// hook\n# provides = [\"a\"]\n# provides = [\"b\"]\n# ///\n";
        assert!(parse_block(text).unwrap_err().contains("duplicate key"));
    }

    #[test]
    fn malformed_array_is_an_error() {
        let err = parse_block("# /// hook\n# provides = [bare]\n# ///\n").unwrap_err();
        assert!(err.contains("double-quoted"), "{err}");
    }

    #[test]
    fn trailing_comma_is_allowed() {
        let p = parse_block("# /// hook\n# provides = [\"a\", \"b\",]\n# ///\n").unwrap();
        assert_eq!(p.provides, ["a", "b"]);
    }

    // --- resolve ---------------------------------------------------------

    fn order_of(hooks: &[Hook]) -> Vec<String> {
        resolve(hooks).unwrap().order
    }

    #[test]
    fn requires_orders_after_provides() {
        let hooks = vec![hook("b.sh", &[], &["x"]), hook("a.sh", &["x"], &[])];
        assert_eq!(order_of(&hooks), ["/hooks/a.sh", "/hooks/b.sh"]);
    }

    #[test]
    fn independent_constrained_hooks_keep_name_order() {
        // Two hooks with no edge between them: tie-break is the name.
        let hooks = vec![hook("z.sh", &["z"], &[]), hook("a.sh", &["a"], &[])];
        assert_eq!(order_of(&hooks), ["/hooks/a.sh", "/hooks/z.sh"]);
    }

    #[test]
    fn unconstrained_hooks_run_last_in_name_order() {
        let hooks = vec![
            hook("z-free.sh", &[], &[]),
            hook("a-free.sh", &[], &[]),
            hook("m-dep.sh", &["m"], &[]),
        ];
        assert_eq!(
            order_of(&hooks),
            ["/hooks/m-dep.sh", "/hooks/a-free.sh", "/hooks/z-free.sh"],
        );
    }

    #[test]
    fn no_block_hook_warns_and_runs_last() {
        let mut nb = hook("late.sh", &[], &[]);
        nb.has_block = false;
        let hooks = vec![nb, hook("early.sh", &["e"], &[])];
        let r = resolve(&hooks).unwrap();
        assert_eq!(r.order, ["/hooks/early.sh", "/hooks/late.sh"]);
        assert_eq!(r.warnings.len(), 1);
        assert!(r.warnings[0].contains("late.sh"));
    }

    #[test]
    fn cycle_is_rejected() {
        let hooks = vec![hook("a.sh", &["a"], &["b"]), hook("b.sh", &["b"], &["a"])];
        let err = resolve(&hooks).unwrap_err();
        assert!(err.contains("cycle"), "{err}");
        assert!(err.contains("a.sh") && err.contains("b.sh"), "{err}");
    }

    #[test]
    fn unsatisfied_requires_is_rejected() {
        let hooks = vec![hook("a.sh", &[], &["nonexistent"])];
        let err = resolve(&hooks).unwrap_err();
        assert!(err.contains("no hook provides"), "{err}");
    }

    #[test]
    fn multiple_providers_order_after_all_of_them() {
        // c requires `cap`; both a and b provide it — c must run last.
        let hooks = vec![
            hook("c.sh", &[], &["cap"]),
            hook("a.sh", &["cap"], &[]),
            hook("b.sh", &["cap"], &[]),
        ];
        assert_eq!(order_of(&hooks), ["/hooks/a.sh", "/hooks/b.sh", "/hooks/c.sh"]);
    }

    // --- render_seq ------------------------------------------------------

    #[test]
    fn render_seq_starts_with_the_version_line() {
        let seq = render_seq(&["/hooks/a.sh".to_string()]);
        let text = String::from_utf8(seq).unwrap();
        assert_eq!(text, "hookseq 1\n/hooks/a.sh\n");
    }

    #[test]
    fn render_seq_with_no_hooks_is_just_the_version_line() {
        assert_eq!(render_seq(&[]), b"hookseq 1\n");
    }

    // --- discover --------------------------------------------------------

    #[test]
    fn discover_reads_and_name_sorts_hooks() {
        let dir = tempdir().unwrap();
        let d = dir.path();
        fs::write(d.join("b.sh"), "#!/bin/sh\n# /// hook\n# requires = [\"x\"]\n# ///\n").unwrap();
        fs::write(d.join("a.sh"), "#!/bin/sh\n# /// hook\n# provides = [\"x\"]\n# ///\n").unwrap();
        fs::write(d.join("c.sh"), "#!/bin/sh\necho no block\n").unwrap();

        let got = discover(d).unwrap();
        let names: Vec<&str> = got.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(names, ["a.sh", "b.sh", "c.sh"]);
        assert_eq!(got[0].provides, ["x"]);
        assert_eq!(got[1].requires, ["x"]);
        assert!(!got[2].has_block);
    }

    #[test]
    fn discover_propagates_a_malformed_block() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("bad.sh"), "# /// hook\n# nope = [\"x\"]\n# ///\n").unwrap();
        let err = discover(dir.path()).unwrap_err().to_string();
        assert!(err.contains("bad.sh") && err.contains("unknown key"), "{err}");
    }
}
