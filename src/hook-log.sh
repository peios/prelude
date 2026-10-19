# shellcheck shell=sh
# The Peios boot console line format, for initramfs hook scripts.
#
# Source it and report outcomes through the helpers instead of bare `echo`:
#
#     . /usr/libexec/prelude/hook-log.sh
#     hook_log_init stratafs-base
#
#     log_ok   "mounted $target"
#     log_warn "$target is already mounted; leaving it alone"
#     log_fail "mount $target failed"
#     log      "mounting $target"          # progress, no outcome yet
#
# which produces, aligned with everything prelude and peinit write:
#
#     [  OK  ] stratafs-base: mounted /bin
#     [ WARN ] stratafs-base: /bin is already mounted; leaving it alone
#     [FAILED] stratafs-base: mount /bin failed
#     [      ] stratafs-base: mounting /bin
#
# WHY A SOURCED FILE AND NOT SOMETHING PRELUDE DOES FOR YOU
#
# prelude runs hooks with a bare fork/execve and no pipe: a hook inherits
# prelude's stdout and stderr and writes to the console directly. prelude never
# sees a byte of a hook's output and so cannot tag, prefix or align it. That is
# a deliberate property of a PID 1 that avoids machinery, not an oversight —
# but it does mean the only place a hook's lines can be formatted is inside the
# hook. Hence this file.
#
# Requires prelude-hook-abi >= 3, which is the level that ships it.

# The component name that prefixes every line. Call once, at the top.
#
# Use the hook's own name — the thing an operator would grep for — not the file
# name and not "prelude": these lines are yours, and attributing them to prelude
# is how a hook's failure gets read as prelude's.
hook_log_init() {
    HOOK_LOG_COMPONENT="$1"

    # Colour follows the same rule as prelude and peinit: on unless the kernel
    # command line declares the terminal dumb. A hook has no inherited TERM
    # worth trusting this early, and reading /proc/cmdline is what its two
    # parents do.
    HOOK_LOG_COLOUR=1
    if [ -r /proc/cmdline ]; then
        # Kernel command-line settings are whitespace-separated words.
        # shellcheck disable=SC2013
        for _tok in $(cat /proc/cmdline); do
            case "$_tok" in
            TERM=dumb) HOOK_LOG_COLOUR=0 ;;
            TERM=*) HOOK_LOG_COLOUR=1 ;;
            esac
        done
        unset _tok
    fi
}

# Internal: render one line. $1 is the six-character tag body, $2 the SGR
# parameters (empty for none), $3 the message.
_hook_log_emit() {
    _tag=$1
    _sgr=$2
    _msg=$3
    if [ "${HOOK_LOG_COLOUR:-1}" = 1 ] && [ -n "$_sgr" ]; then
        # Only the fixed format interprets escapes. Component and message
        # text are literal even when filenames contain backslashes or %.
        printf '[\033[%sm%s\033[0m] %s: %s\n' \
            "$_sgr" "$_tag" "${HOOK_LOG_COMPONENT:-hook}" "$_msg"
    else
        printf '%s\n' "[${_tag}] ${HOOK_LOG_COMPONENT:-hook}: ${_msg}"
    fi
    unset _tag _sgr _msg
}

# Progress with no outcome yet. Blank bracket: it holds the column while
# receding, so OK and FAILED are what catch the eye.
log() { _hook_log_emit '      ' '' "$*"; }

# It worked. Past tense, please — the tag already claims the outcome, so
# "mounted /bin" and never "mounting /bin".
log_ok() { _hook_log_emit '  OK  ' '1;32' "$*"; }

# Deliberately not done.
log_skip() { _hook_log_emit ' SKIP ' '1;33' "$*"; }

# Wrong, but the boot continues. To stderr, like log_fail: a hook's warnings
# should survive a caller that is capturing stdout.
log_warn() { _hook_log_emit ' WARN ' '1;33' "$*" >&2; }

# It did not work.
log_fail() { _hook_log_emit 'FAILED' '1;31' "$*" >&2; }
