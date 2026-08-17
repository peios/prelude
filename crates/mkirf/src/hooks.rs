//! Hook DAG — discover initramfs hooks, parse their co-located metadata,
//! and resolve a deterministic execution order.
//!
//! A hook is a regular file directly under `<src>/hooks/`. prelude runs
//! hooks, in the order resolved here, inside the initramfs before
//! switch_root. Each hook declares its ordering in a fenced comment block
//! (PEP 723-style); mkirf topologically sorts the resulting capability
//! DAG and bakes the order into `hooks.seq`. See boot-design.md §3.6.
//!
//! # The four ordering keys
//!
//! A capability is *supplied* in one of two ways, and consumed in one of
//! two ways. Which pair a hook uses is the whole of its ordering.
//!
//! | key | kind | meaning |
//! |---|---|---|
//! | `provides` | supply | an ALTERNATIVE — any one provider suffices |
//! | `contributes` | supply | a CONTRIBUTOR — all of them must complete |
//! | `requires` | consume | hard: something must supply it, or the build fails |
//! | `after` | consume | soft: order after it if anything supplies it, else just run |
//!
//! `contributes` is what makes "run *before* X" expressible at all. A hook
//! is otherwise ordered only by what it consumes, so running before the
//! root is mounted would mean the root-mount hooks naming a hook that did
//! not exist when they were packaged. Declaring yourself part of X inverts
//! that: anything consuming X now waits for you.
//!
//! `after` is what makes a shared capability vocabulary survivable. A hard
//! `requires` on a name nothing supplies is a build error, so a standard
//! name like `network-up` would break every image without networking the
//! moment anything mentioned it.
//!
//! The alternatives/contributors distinction does not change the ORDER —
//! both put suppliers before consumers — so this module treats them alike
//! when building edges. It changes what a runtime scheduler may skip, and
//! is enforced here only as a validity rule: a capability may not be both.

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
    /// Capabilities this hook satisfies on its own — alternatives, any one
    /// of which suffices.
    pub provides: Vec<String>,
    /// Capabilities this hook is one contributor to. Every contributor must
    /// complete before the capability is satisfied.
    pub contributes: Vec<String>,
    /// Capabilities that must be satisfied before this hook runs. Something
    /// must supply each of them or the build fails.
    pub requires: Vec<String>,
    /// Capabilities to be ordered after *if anything supplies them*. Unlike
    /// `requires`, an unsupplied name is not an error — the constraint
    /// simply has nothing to attach to.
    pub after: Vec<String>,
    /// Whether the hook carried a `# /// hook` metadata block at all.
    /// A hook with no block is the escape hatch (§3.6): valid, but
    /// scheduled last and warned about.
    pub has_block: bool,
}

impl Hook {
    /// Capabilities this hook supplies, by either means. Ordering treats
    /// the two alike; only validity and a runtime scheduler tell them apart.
    fn supplies(&self) -> impl Iterator<Item = &str> + '_ {
        self.provides.iter().chain(self.contributes.iter()).map(String::as_str)
    }

    /// Capabilities this hook waits on, by either means.
    fn consumes(&self) -> impl Iterator<Item = &str> + '_ {
        self.requires.iter().chain(self.after.iter()).map(String::as_str)
    }

    /// Whether the hook declared any ordering at all. One that declared
    /// none runs after every hook that did.
    fn is_constrained(&self) -> bool {
        self.supplies().next().is_some() || self.consumes().next().is_some()
    }
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
            contributes: parsed.contributes,
            requires: parsed.requires,
            after: parsed.after,
            has_block: parsed.has_block,
        });
    }
    hooks.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
    Ok(hooks)
}

/// The metadata extracted from a single hook script.
#[derive(Debug, Default)]
struct Parsed {
    provides: Vec<String>,
    contributes: Vec<String>,
    requires: Vec<String>,
    after: Vec<String>,
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
        return Ok(Parsed::default());
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

    let mut parsed = parse_toml_subset(&content)?;
    parsed.has_block = true;
    Ok(parsed)
}

/// Parse the metadata block's content — the TOML subset mkirf accepts:
/// blank lines, `#` comments, and top-level `key = ["str", ...]`
/// assignments where `key` is one of the four ordering keys.
fn parse_toml_subset(content: &[(usize, String)]) -> Result<Parsed, String> {
    let mut provides: Option<Vec<String>> = None;
    let mut contributes: Option<Vec<String>> = None;
    let mut requires: Option<Vec<String>> = None;
    let mut after: Option<Vec<String>> = None;

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
            "contributes" => &mut contributes,
            "requires" => &mut requires,
            "after" => &mut after,
            other => {
                return Err(format!(
                    "line {lineno}: unknown key `{other}` \
                     (expected `provides`, `contributes`, `requires` or `after`)"
                ))
            }
        };
        if slot.is_some() {
            return Err(format!("line {lineno}: duplicate key `{}`", key.trim()));
        }
        *slot = Some(parse_string_array(value.trim()).map_err(|e| format!("line {lineno}: {e}"))?);
    }

    Ok(Parsed {
        provides: provides.unwrap_or_default(),
        contributes: contributes.unwrap_or_default(),
        requires: requires.unwrap_or_default(),
        after: after.unwrap_or_default(),
        has_block: false,
    })
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
/// Constrained hooks — those declaring any of the four ordering keys — are
/// ordered by their capability DAG: Kahn's algorithm, ties broken by file
/// name in `LC_ALL=C` byte order. Unconstrained hooks (every list empty,
/// block present or not) run afterwards in name order.
///
/// Three things are errors: a dependency cycle, a `requires` nothing
/// supplies, and a capability that is both provided and contributed to.
pub fn resolve(hooks: &[Hook]) -> Result<Resolved, String> {
    // Work from a name-sorted view so the result does not depend on the
    // order `discover` happened to return.
    let mut sorted: Vec<&Hook> = hooks.iter().collect();
    sorted.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));

    let (constrained, unconstrained): (Vec<&Hook>, Vec<&Hook>) =
        sorted.into_iter().partition(|h| h.is_constrained());

    // A capability is either a set of alternatives or a set of contributors.
    // Mixing the two leaves no answer to "is it satisfied yet?" — the
    // alternatives say one is enough, the contributors say all are needed —
    // so it is rejected here rather than resolved arbitrarily at boot.
    let provided: BTreeSet<&str> =
        hooks.iter().flat_map(|h| h.provides.iter().map(String::as_str)).collect();
    let contributed: BTreeSet<&str> =
        hooks.iter().flat_map(|h| h.contributes.iter().map(String::as_str)).collect();
    if let Some(&cap) = provided.intersection(&contributed).next() {
        let providers = named_hooks(hooks, |h| h.provides.iter().any(|c| c == cap));
        let contributors = named_hooks(hooks, |h| h.contributes.iter().any(|c| c == cap));
        return Err(format!(
            "capability `{cap}` is both provided (by {providers}) and contributed to \
             (by {contributors}); a capability is either alternatives, where one \
             supplier suffices, or contributors, where all must complete — not both",
        ));
    }

    // Every hard requirement must be supplied by some hook, by either means.
    // `after` is deliberately exempt: an unsupplied soft edge simply has
    // nothing to attach to, which is the whole reason it exists.
    let all_supplied: BTreeSet<&str> = provided.union(&contributed).copied().collect();
    for h in &constrained {
        for req in &h.requires {
            if !all_supplied.contains(req.as_str()) {
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

/// A comma-separated, name-sorted list of the hooks matching `pred`, for
/// error messages that have to name who caused the problem.
fn named_hooks(hooks: &[Hook], pred: impl Fn(&Hook) -> bool) -> String {
    let mut names: Vec<&str> =
        hooks.iter().filter(|h| pred(h)).map(|h| h.name.as_str()).collect();
    names.sort_unstable_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    names.join(", ")
}

/// Kahn's algorithm over the constrained hooks. Returns indices into
/// `constrained` in execution order, or an error naming the hooks caught
/// in a dependency cycle.
fn kahn_sort(constrained: &[&Hook]) -> Result<Vec<usize>, String> {
    let n = constrained.len();

    // capability -> indices of constrained hooks that supply it. Providers
    // and contributors both land here: the two differ in what a runtime
    // scheduler may skip, not in who runs first.
    let mut suppliers: HashMap<&str, Vec<usize>> = HashMap::new();
    for (i, h) in constrained.iter().enumerate() {
        for cap in h.supplies() {
            suppliers.entry(cap).or_default().push(i);
        }
    }

    // Edges p -> c: supplier p must run before consumer c. `requires` and
    // `after` produce the same edge — they differ only in whether an
    // unsupplied capability is an error, which `resolve` has already
    // decided by this point. A BTreeSet dedups (a supplier supplying two
    // capabilities one hook consumes) and keeps iteration deterministic.
    let mut edge_set: BTreeSet<(usize, usize)> = BTreeSet::new();
    for (c, h) in constrained.iter().enumerate() {
        for cap in h.consumes() {
            for &p in suppliers.get(cap).into_iter().flatten() {
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

    fn strs(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    /// Build a hook with a metadata block present, declaring only the two
    /// original keys — the shape most of these tests need.
    fn hook(name: &str, provides: &[&str], requires: &[&str]) -> Hook {
        hook4(name, provides, &[], requires, &[])
    }

    /// Build a hook declaring any of the four ordering keys.
    fn hook4(
        name: &str,
        provides: &[&str],
        contributes: &[&str],
        requires: &[&str],
        after: &[&str],
    ) -> Hook {
        Hook {
            name: name.to_string(),
            provides: strs(provides),
            contributes: strs(contributes),
            requires: strs(requires),
            after: strs(after),
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
        // The message lists what IS accepted, so a typo is self-correcting.
        assert!(err.contains("contributes") && err.contains("after"), "{err}");
    }

    #[test]
    fn all_four_keys_are_parsed() {
        let text = "#!/bin/sh\n\
                     # /// hook\n\
                     # provides = [\"root-mounted\"]\n\
                     # contributes = [\"storage-ready\"]\n\
                     # requires = [\"modules-loaded\"]\n\
                     # after = [\"network-up\"]\n\
                     # ///\n";
        let p = parse_block(text).unwrap();
        assert_eq!(p.provides, ["root-mounted"]);
        assert_eq!(p.contributes, ["storage-ready"]);
        assert_eq!(p.requires, ["modules-loaded"]);
        assert_eq!(p.after, ["network-up"]);
    }

    #[test]
    fn duplicate_contributes_is_an_error() {
        let text = "# /// hook\n# contributes = [\"a\"]\n# contributes = [\"b\"]\n# ///\n";
        assert!(parse_block(text).unwrap_err().contains("duplicate key"));
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

    // --- contributes -----------------------------------------------------

    #[test]
    fn contributes_orders_before_the_consumer() {
        // The "before" case the model could not express: a hook declares
        // itself part of a capability, and the consumer waits for it.
        let hooks = vec![
            hook("z-consumer.sh", &[], &["storage-ready"]),
            hook4("a-part.sh", &[], &["storage-ready"], &[], &[]),
        ];
        assert_eq!(order_of(&hooks), ["/hooks/a-part.sh", "/hooks/z-consumer.sh"]);
    }

    #[test]
    fn contributes_satisfies_a_hard_requires() {
        // A capability supplied only by contributors is still supplied.
        let hooks = vec![
            hook("consumer.sh", &[], &["storage-ready"]),
            hook4("part.sh", &[], &["storage-ready"], &[], &[]),
        ];
        assert!(resolve(&hooks).is_ok());
    }

    #[test]
    fn every_contributor_runs_before_the_consumer() {
        let hooks = vec![
            hook("d-consumer.sh", &[], &["cap"]),
            hook4("a-part.sh", &[], &["cap"], &[], &[]),
            hook4("b-part.sh", &[], &["cap"], &[], &[]),
        ];
        assert_eq!(
            order_of(&hooks),
            ["/hooks/a-part.sh", "/hooks/b-part.sh", "/hooks/d-consumer.sh"],
        );
    }

    #[test]
    fn a_capability_cannot_be_both_provided_and_contributed() {
        let hooks = vec![
            hook("alt.sh", &["cap"], &[]),
            hook4("part.sh", &[], &["cap"], &[], &[]),
        ];
        let err = resolve(&hooks).unwrap_err();
        assert!(err.contains("both provided"), "{err}");
        // Both sides are named, so the conflict is actionable.
        assert!(err.contains("alt.sh") && err.contains("part.sh"), "{err}");
    }

    // --- after -----------------------------------------------------------

    #[test]
    fn after_orders_when_the_capability_is_supplied() {
        let hooks = vec![
            hook4("a-late.sh", &[], &[], &[], &["net"]),
            hook("z-net.sh", &["net"], &[]),
        ];
        // Name order would put a-late.sh first; the soft edge overrides it.
        assert_eq!(order_of(&hooks), ["/hooks/z-net.sh", "/hooks/a-late.sh"]);
    }

    #[test]
    fn after_an_unsupplied_capability_is_not_an_error() {
        // The whole point of `after`: naming a capability this image does
        // not have must not break the build the way `requires` does.
        let hooks = vec![hook4("solo.sh", &[], &[], &[], &["network-up"])];
        let r = resolve(&hooks).unwrap();
        assert_eq!(r.order, ["/hooks/solo.sh"]);
    }

    #[test]
    fn after_alone_still_counts_as_constrained() {
        // A hook declaring only `after` has stated an ordering intent, so it
        // belongs in the DAG rather than in the unconstrained tail.
        let hooks = vec![
            hook4("a-soft.sh", &[], &[], &[], &["absent"]),
            hook("z-free.sh", &[], &[]),
        ];
        assert_eq!(order_of(&hooks), ["/hooks/a-soft.sh", "/hooks/z-free.sh"]);
    }

    #[test]
    fn after_is_satisfied_by_a_contributor_too() {
        let hooks = vec![
            hook4("a-late.sh", &[], &[], &[], &["cap"]),
            hook4("z-part.sh", &[], &["cap"], &[], &[]),
        ];
        assert_eq!(order_of(&hooks), ["/hooks/z-part.sh", "/hooks/a-late.sh"]);
    }

    #[test]
    fn a_cycle_through_after_is_still_rejected() {
        // Soft edges are still edges: they cannot be used to smuggle in an
        // unorderable set.
        let hooks = vec![
            hook4("a.sh", &["a"], &[], &[], &["b"]),
            hook4("b.sh", &["b"], &[], &[], &["a"]),
        ];
        assert!(resolve(&hooks).unwrap_err().contains("cycle"));
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
