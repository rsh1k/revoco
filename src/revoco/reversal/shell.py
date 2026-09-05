"""Classifying what a shell command can and cannot be taken back from.

Ported from irredux. revoco classifies a *tool call* — a name and arguments —
and a shell command is neither, so every one of them fell through to UNKNOWN and
was treated as one-way. Safe, and useless: an agent that cannot run `ls` without
an escalation is an agent nobody keeps switched on.

One deliberate divergence from the original, which had no posture for an action
that changes nothing and so called a read REVERSIBLE. Here a read-only command
is IDEMPOTENT — the same distinction that stopped `fs.read_file` being drilled
as though it had an inverse to prove.

This is the hard part of guarding a coding agent, and the part most likely to be
wrong, so the reasoning is written down rather than left in the patterns.

The question is not "is this dangerous"
---------------------------------------
It is **"can a snapshot of the working tree undo this?"** Those are different
questions and the difference is the whole design.

``rm -rf build/`` looks alarming and is completely recoverable if a snapshot was
taken first. ``curl -X POST https://api.example.com/charge`` looks routine and
cannot be taken back by any mechanism that exists. A guard that ranked those by how
scary they read would block the wrong one.

So commands sort by **what escapes the snapshot**:

``READ_ONLY``
    Cannot change anything. No snapshot needed, no prompt, no cost.

``LOCAL``
    Changes the working tree and nothing else. A snapshot taken beforehand makes it
    reversible *by construction*, whatever the command actually was.

``ESCAPES``
    Reaches past the working tree — the network, a remote, a registry, a cloud
    account, another machine. No local snapshot helps. These are the one-way doors.

``UNKNOWN``
    Could not be classified.

Why unknown does not mean "block"
---------------------------------
Everywhere else in this package, unknown resolves to maximum severity. Here it
resolves to *snapshot and allow*, and that is a deliberate exception rather than an
oversight.

A coding agent runs hundreds of shell commands per session, most of them
unremarkable and many of them unclassifiable by any pattern list. Prompting on each
one produces a guard that gets switched off within an hour, and a guard that is off
protects nothing — the same reasoning that keeps the human gate off reversible work
in :mod:`irredux.policy`.

The resolution is that the snapshot changes what "unknown" costs. Rather than
predicting every command, take a cheap snapshot and make the unpredicted ones
recoverable. That is the thesis of this whole project applied to itself: you do not
need to know what will go wrong, you need to be able to take it back.

What that does *not* cover is stated plainly in :data:`ESCAPE_PATTERNS` — anything
that leaves the machine is still a one-way door, and those still prompt.

Compound commands
-----------------
``ls && rm -rf ~`` must not be classified by ``ls``. Commands are split on shell
operators and the **most severe** part decides. Anything containing a construct that
cannot be read statically — command substitution, ``eval``, a pipe into a shell —
is ``UNKNOWN``, because the text no longer tells you what will run.
"""

from __future__ import annotations

import enum
import os
import re
import shlex
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

from .model import InverseSpec, Reversibility


@enum.unique
class Reach(enum.Enum):
    """How far a command's effects extend beyond the working tree."""

    READ_ONLY = "read_only"
    """Cannot change anything. No snapshot needed."""

    LOCAL = "local"
    """Changes the working tree and nothing beyond it. A snapshot covers it."""

    ESCAPES = "escapes"
    """Reaches the network, a remote, a registry, or another account."""

    UNKNOWN = "unknown"
    """Not classifiable from the text."""

    @property
    def rank(self) -> int:
        """Ascending severity."""
        match self:
            case Reach.READ_ONLY:
                return 0
            case Reach.LOCAL:
                return 1
            # Unknown ranks *below* escapes: an unclassified command is more likely
            # to be a local build step than an outbound payment, and the snapshot
            # covers the local case. Escapes are ranked highest because no local
            # mechanism recovers from them.
            case Reach.UNKNOWN:
                return 2
            case Reach.ESCAPES:
                return 3
        _unreachable(self)

    def worst(self, other: Reach) -> Reach:
        """The more severe of two reaches. Raises only."""
        return other if other.rank > self.rank else self


# Commands that cannot modify anything. Deliberately a short, boring list: a wrong
# entry here means a mutating command is allowed with no snapshot, which is the one
# failure in this module that loses data. Anything not listed falls through to a
# more cautious branch, so the cost of omission is a snapshot nobody needed.
READ_ONLY_COMMANDS = frozenset({
    "awk", "basename", "cat", "cksum", "column", "comm", "cut", "date", "df",
    "diff", "dirname", "du", "echo", "env", "false", "file", "find", "grep",
    "head", "hostname", "id", "jq", "less", "ls", "md5sum", "more", "nl", "od",
    "printenv", "printf", "ps", "pwd", "readlink", "realpath", "rg", "sed",
    "seq", "sha1sum", "sha256sum", "sleep", "sort", "stat", "tail", "tee",
    "test", "top", "tr", "true", "type", "uname", "uniq", "uptime", "wc",
    "whereis", "which", "who", "whoami", "xxd", "yes",
    # Shell builtins that bind a variable or change process state. None of them
    # touch the filesystem, and `read` in particular leads `while read line`, which
    # is one of the commonest loop headers there is.
    "read", "local", "declare", "typeset", "set", "unset", "shift", "export",
    "return", "break", "continue", "exit", "trap", "alias", "let", "getopts",
    # Added from a real session's unknown bucket. Each reads or prints and
    # cannot modify the working tree on its own.
    "base64", "cmp", "dig", "expr", "host", "join", "locale", "look",
    "nproc", "ping", "pgrep", "sha512sum", "strings", "tty",
    "uuidgen", "wait", "watch", "xargs-noop",
})

# Subcommands of otherwise-mutating tools that only read.
READ_ONLY_SUBCOMMANDS: dict[str, frozenset[str]] = {
    "git": frozenset({
        "status", "log", "diff", "show", "branch", "remote", "config",
        "rev-parse", "describe", "blame", "ls-files", "ls-tree", "cat-file",
        "shortlog", "reflog", "count-objects", "check-ignore", "grep",
    }),
    "docker": frozenset({"ps", "images", "inspect", "logs", "version", "info"}),
    "kubectl": frozenset({"get", "describe", "logs", "explain", "version", "top"}),
    "npm": frozenset({"ls", "list", "view", "outdated", "audit", "why"}),
    "pip": frozenset({"list", "show", "freeze", "check"}),
    "uv": frozenset({"tree", "version"}),
    "cargo": frozenset({"tree", "metadata", "search"}),
    "gh": frozenset({"status", "browse", "search", "auth", "config", "label", "ruleset"}),
    "python": frozenset(),   # never read-only; falls through to the write branch
    "python3": frozenset(),
    "make": frozenset(),
    "pytest": frozenset(),
    "pipx": frozenset({"list"}),
    "curl": frozenset(),
    "terraform": frozenset({"plan", "show", "validate", "fmt", "version", "output"}),
}


@dataclass(frozen=True, slots=True)
class EscapeRule:
    """A pattern that marks a command as leaving the working tree."""

    pattern: re.Pattern[str]
    why: str
    """Shown to the user. Says what cannot be undone, not that something is scary."""


def _rule(regex: str, why: str) -> EscapeRule:
    return EscapeRule(re.compile(regex, re.IGNORECASE), why)


# One-way doors. Each entry is something no local snapshot can reverse.
#
# The `why` strings matter as much as the patterns. A prompt saying "dangerous
# command" teaches nothing and gets click-throughed; one saying "this pushes to a
# remote others may already have fetched" is a decision the reader can actually make.
ESCAPE_PATTERNS: tuple[EscapeRule, ...] = (
    # --- version control, outbound ---
    _rule(r"\bgit\s+push\b.*(--force|--delete|-f\b)",
          "force-pushes or deletes a remote ref; anyone who already fetched keeps the old history"),
    _rule(r"\bgit\s+push\b", "publishes commits to a remote; a local undo does not retract them"),
    _rule(r"\bgit\s+tag\b.*\s-d\b.*", "deletes a tag others may already have fetched"),
    # --- code hosting ---
    _rule(r"\bgh\s+(pr\s+merge|release\s+create|repo\s+delete|api\s+.*-X\s*(POST|PUT|PATCH|DELETE))",
          "changes state on GitHub, outside anything this machine can restore"),
    # --- package registries: immutable once published ---
    _rule(r"\bnpm\s+(publish|unpublish)\b", "publishes to npm; registry versions are immutable"),
    _rule(r"\b(twine\s+upload|uv\s+publish|flit\s+publish)\b",
          "publishes to PyPI; versions cannot be replaced, only yanked"),
    _rule(r"\bcargo\s+publish\b", "publishes to crates.io; versions are permanent"),
    _rule(r"\bdocker\s+(push)\b", "pushes an image to a registry"),
    # --- cloud and infrastructure ---
    _rule(r"\bterraform\s+(apply|destroy)\b", "changes real infrastructure"),
    _rule(r"\b(aws|gcloud|az)\s+", "acts on a cloud account; nothing local reverses it"),
    _rule(r"\bkubectl\s+(apply|delete|scale|patch|replace|drain|cordon|rollout)\b",
          "changes cluster state"),
    _rule(r"\bhelm\s+(install|upgrade|uninstall|rollback)\b", "changes cluster state"),
    # --- outbound network with a body or a mutating method ---
    _rule(r"\bcurl\b(?=.*(-X\s*(POST|PUT|PATCH|DELETE)|--data|-d\s|--upload-file|-T\s))",
          "sends data to a remote service; the request cannot be recalled"),
    _rule(r"\bwget\b.*(--post-data|--post-file|--method=(POST|PUT|PATCH|DELETE))",
          "sends data to a remote service"),
    _rule(r"\bhttpie?\b.*\b(POST|PUT|PATCH|DELETE)\b", "sends data to a remote service"),
    _rule(r"\bssh\b\s+\S+\s+\S", "runs a command on another machine, outside this snapshot"),
    _rule(r"\b(scp|rsync)\b.*\S+:", "copies to or from another machine"),
    # --- messaging: cannot be unsent ---
    _rule(r"\b(sendmail|mailx?|mutt)\b", "sends mail; it cannot be unsent"),
    # --- databases: a snapshot of the working tree does not cover a server ---
    _rule(r"\b(psql|mysql|mongosh|redis-cli)\b.*(DROP|DELETE|TRUNCATE|FLUSHALL)",
          "destructive statement against a database server"),
    # --- privilege escalation puts changes outside the snapshot ---
    _rule(r"\bsudo\b", "runs as root; changes outside the working tree are not snapshotted"),
    # --- disk-level, unrecoverable even locally ---
    _rule(r"\b(mkfs|fdisk|dd)\b", "writes at the device level"),
    _rule(r"\bshred\b", "overwrites data specifically so it cannot be recovered"),
)

# Constructs whose effect cannot be read from the text. Each makes the whole command
# UNKNOWN rather than letting a benign-looking prefix decide.
OPAQUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\$\("),          # command substitution
    re.compile(r"`"),             # legacy command substitution
    re.compile(r"\beval\b"),
    re.compile(r"\bexec\b"),
    re.compile(r"\|\s*(ba|z|k)?sh\b"),   # curl ... | sh
    re.compile(r"\bxargs\b"),
    re.compile(r"\bsource\b|^\s*\."),
)

# Commands that move around or inspect without writing anything to the paths they
# name. `cd` is the one that matters: it appeared in seven of thirteen escalations
# in a real session, every one a false prompt, because the path check saw an
# argument outside the snapshot root and could not tell that `cd` never writes.
# Commands that write, and write only where they are told. Every one of these is
# recoverable from a snapshot of the directory it touched, which is what LOCAL
# means — and the path check below still promotes any of them to ESCAPES when an
# argument points outside the snapshot root.
#
# This set does not exist in the original, where an unrecognised writer fell to
# UNKNOWN and that was fine: there UNKNOWN means "snapshot it and carry on". Here
# it does not. revoco ranks UNKNOWN *below* IRREVERSIBLE on purpose — an
# unclassified action is worse than a known one-way door, because with the latter
# you at least know to ask — so an UNKNOWN posture fails every reversibility
# floor a policy can state. Ported unchanged, `rm -rf build/` would have been
# refused by a policy that permits reversible writes, which is the "safe and
# useless" outcome this module's own docstring warns about.
#
# Anything not named here still falls to UNKNOWN. The set is deliberately short:
# the cost of omitting a command is one escalation, and the cost of wrongly
# calling something local is an undo that was never possible.
LOCAL_WRITE_COMMANDS = frozenset({
    "rm", "rmdir", "mv", "cp", "mkdir", "touch", "ln", "chmod", "chown",
    "truncate", "install", "patch", "split", "gzip", "gunzip", "bzip2", "xz",
    "zip", "unzip", "tar",
})

NAVIGATION_COMMANDS = frozenset({"cd", "pushd", "popd", "dirs"})

# Shell control flow. These lead a fragment without being the command that runs,
# so `for f in *.py` and `do wc -l $f` were classifying as unrecognised programs
# named `for` and `do`. They accounted for the two largest entries in the unknown
# bucket of a real session. Skipping them lets the actual command decide.
# Keywords to step past so the real command decides. `if grep -q x f` runs grep,
# so the keyword is noise rather than the subject.
SHELL_KEYWORDS = frozenset({
    "do", "done", "if", "then", "elif", "else", "fi", "while", "until",
    "esac", "function", "{", "}", "!", "[[", "]]",
})

# Headers that bind a variable and run nothing. `for f in *.py` executes no
# command at all — stepping past `for` left `f`, the loop variable, looking like
# an unrecognised program, which is how a loop over `wc -l` came out UNKNOWN.
CONTROL_HEADERS = frozenset({"for", "select", "case"})

# Matches a heredoc introducer so its body can be removed before classification.
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")

# Splits on shell operators AND newlines so each part is classified separately.
#
# Newlines were missing, and that was a hole rather than an omission: a multi-line
# block came through as a single fragment, so `_classify_simple` saw only its first
# token and `echo hi\nrm -rf ~` classified as READ_ONLY — no prompt, and no
# snapshot either, since read-only work is not snapshotted. Escape *patterns* still
# matched, because those run against the whole text, which is why the hole showed
# up only for the path rule and the read-only fast path.
_SEPARATORS = re.compile(r"\s*(?:&&|\|\||;|\||\n)\s*")


@dataclass(frozen=True, slots=True)
class ShellVerdict:
    """What a shell command can be taken back from."""

    reach: Reach
    reversibility: Reversibility
    why: str
    """A sentence the user can act on. Empty when nothing needs saying."""

    needs_snapshot: bool
    """Whether a snapshot must be taken before this runs."""


def _unreachable(value: NoReturn) -> NoReturn:
    """Exhaustiveness check that works on the Python versions this supports.

    ``typing.assert_never`` arrived in 3.11 and this package supports 3.10 —
    which the local interpreter could not reveal, because its stubs have the
    symbol, so mypy passed here and failed in CI. Typing the parameter
    ``NoReturn`` is the older idiom and gives the same static guarantee: a new
    ``Reach`` member left unhandled below is a type error rather than a runtime
    surprise.
    """
    raise AssertionError(f"unhandled reach: {value!r}")


def _strip_heredocs(text: str) -> str:
    """Remove heredoc bodies, keeping the command line that introduced them.

    A heredoc body is *data*, not commands, and classifying it as commands was a
    real false-positive source: `cat > deploy.sh <<'EOF' ... git push --force ...
    EOF` matched the force-push pattern and prompted, even though the only thing
    happening is a local file write that a snapshot covers completely.

    The introducing line is kept, so the redirect that makes it a write is still
    seen. Only the payload is dropped.
    """
    lines = text.split("\n")
    out: list[str] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        out.append(line)
        tags = [m.group(2) for m in _HEREDOC.finditer(line)]
        index += 1
        for tag in tags:
            while index < len(lines) and lines[index].strip() != tag:
                index += 1
            index += 1  # skip the terminator itself
    return "\n".join(out)


def classify(command: str, root: str | None = None) -> ShellVerdict:
    """Classify a shell command by what a working-tree snapshot cannot undo.

    ``root`` is the directory the snapshot will cover. Supplying it is what lets a
    mutating command touching paths *outside* that directory be recognised as an
    escape. Omitting it disables that check, so callers that can identify the
    snapshot root should always pass it.
    """
    text = _strip_heredocs(command.strip())
    if not text:
        return ShellVerdict(
            Reach.READ_ONLY, Reversibility.IDEMPOTENT, "", needs_snapshot=False)

    # Escapes are checked against the whole command first. Splitting on operators
    # cannot be trusted to isolate them — quoting and nesting both defeat it — and
    # the cost of a false positive here is one prompt, while the cost of a false
    # negative is an unrecoverable action.
    for rule in ESCAPE_PATTERNS:
        if rule.pattern.search(text):
            return ShellVerdict(
                Reach.ESCAPES, Reversibility.IRREVERSIBLE, rule.why, needs_snapshot=True
            )

    if any(p.search(text) for p in OPAQUE_PATTERNS):
        return ShellVerdict(
            Reach.UNKNOWN,
            Reversibility.UNKNOWN,
            "cannot be read statically, so it is snapshotted rather than predicted",
            needs_snapshot=True,
        )

    base = Path(root).expanduser().resolve() if root else None
    fragments = [f for f in _SEPARATORS.split(text) if f.strip()]

    # A `cd` out of the snapshot root changes what every later fragment's relative
    # paths mean, and the snapshot still covers only the original directory. So
    # navigating away is harmless on its own but makes any subsequent write
    # unrecoverable — which is exactly the distinction between `cd /tmp/x` and
    # `cd /tmp/x && rm -rf .`.
    left_root = any(_navigates_away(f, base) for f in fragments)

    worst = Reach.READ_ONLY
    for part in fragments:
        worst = worst.worst(_classify_simple(part, base))

    if left_root and worst is not Reach.READ_ONLY:
        worst = Reach.ESCAPES

    match worst:
        case Reach.READ_ONLY:
            return ShellVerdict(
                worst, Reversibility.IDEMPOTENT, "", needs_snapshot=False)
        case Reach.LOCAL:
            return ShellVerdict(
                worst, Reversibility.REVERSIBLE,
                "changes the working tree; snapshotted first", needs_snapshot=True,
            )
        case Reach.UNKNOWN:
            return ShellVerdict(
                worst, Reversibility.UNKNOWN,
                "not recognised, so it is snapshotted rather than predicted",
                needs_snapshot=True,
            )
        case Reach.ESCAPES:
            return ShellVerdict(
                worst, Reversibility.IRREVERSIBLE,
                "writes outside the directory being snapshotted, so a local undo "
                "would not reach it",
                needs_snapshot=True,
            )
    _unreachable(worst)


def _escapes_root(token: str, root: Path | None) -> bool:
    """Whether a bare argument names a path the snapshot would not cover.

    This is what stops `rm -rf ~` being treated as an ordinary local delete. The
    command name is unrecognised either way; what makes it unrecoverable is the
    *target*, exactly as reversibility elsewhere is a property of the target rather
    than of the tool.

    Read-only commands are resolved before this runs, so `cat /etc/hosts` is never
    reached — reading outside the root is fine, writing outside it is not.
    """
    if root is None or not token or token.startswith("-"):
        return False
    if "://" in token:
        return False  # a URL, handled by the escape patterns
    if not (token.startswith(("/", "~", "./", "../")) or "/" in token or token == ".."):
        return False
    try:
        target = Path(os.path.expandvars(os.path.expanduser(token)))
        resolved = (root / target).resolve() if not target.is_absolute() else target.resolve()
    except (OSError, ValueError, RuntimeError):
        return True  # unresolvable is not a reason to assume it is safe
    return not resolved.is_relative_to(root)


def _navigates_away(fragment: str, root: Path | None) -> bool:
    """Whether this fragment changes directory to somewhere the snapshot misses."""
    if root is None:
        return False
    try:
        tokens = shlex.split(fragment.strip(), comments=True)
    except ValueError:
        return False
    if not tokens or tokens[0].rsplit("/", 1)[-1] not in NAVIGATION_COMMANDS:
        return False
    target = next((t for t in tokens[1:] if not t.startswith("-")), None)
    if target is None:
        # A bare `cd` goes home, which is outside any project root.
        return True
    return _escapes_root(target, root)


def _classify_simple(part: str, root: Path | None = None) -> Reach:
    """Classify one operator-free command fragment."""
    fragment = part.strip()
    if not fragment:
        return Reach.READ_ONLY

    # A redirect writes a file regardless of what produced the output, so `echo hi
    # > important.conf` is not read-only even though `echo` is — and `> /etc/hosts`
    # escapes the snapshot entirely.
    redirect = re.search(r"(?<![0-9<>])>{1,2}\s*(\S+)", fragment)
    if redirect:
        return Reach.ESCAPES if _escapes_root(redirect.group(1), root) else Reach.LOCAL

    try:
        tokens = shlex.split(fragment, comments=True)
    except ValueError:
        # Unbalanced quotes. The text does not say what will run.
        return Reach.UNKNOWN
    if not tokens:
        return Reach.READ_ONLY

    # Skip leading VAR=value assignments and common wrappers.
    index = 0
    while index < len(tokens) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", tokens[index]):
        index += 1
    if index >= len(tokens):
        return Reach.LOCAL  # a bare assignment changes the environment, not the tree
    if tokens[index] in CONTROL_HEADERS:
        # Binds a variable over a word list. The body is a separate fragment and
        # is classified on its own.
        return Reach.READ_ONLY
    while index < len(tokens) and tokens[index] in SHELL_KEYWORDS:
        index += 1
    if index < len(tokens) and tokens[index] in CONTROL_HEADERS:
        return Reach.READ_ONLY
    if index < len(tokens) and tokens[index] in ("command", "nice", "nohup", "time", "env", "sudo-less"):
        index += 1
    if index >= len(tokens):
        return Reach.READ_ONLY

    name = tokens[index].rsplit("/", 1)[-1]
    args = tokens[index + 1 :]

    # Navigation is resolved by the caller, which can see the whole command. On its
    # own it writes nothing, so it must not trip the path check below.
    if name in NAVIGATION_COMMANDS:
        return Reach.READ_ONLY

    if name in READ_ONLY_COMMANDS:
        return Reach.READ_ONLY

    subcommands = READ_ONLY_SUBCOMMANDS.get(name)
    if subcommands is not None:
        sub = next((a for a in args if not a.startswith("-")), None)
        if sub in subcommands:
            return Reach.READ_ONLY

    # Past this point the command can write. If it names a path the snapshot will
    # not cover, no local undo reaches it, whatever the command turns out to be.
    if any(_escapes_root(a, root) for a in args):
        return Reach.ESCAPES

    if name in LOCAL_WRITE_COMMANDS:
        return Reach.LOCAL
    return Reach.LOCAL if subcommands is not None else Reach.UNKNOWN


DEFAULT_SHELL_TOOLS = frozenset({"bash", "sh", "zsh", "shell", "shell.run", "Bash"})


def command_classifier(
    *,
    root: str | None = None,
    shell_tools: frozenset[str] = DEFAULT_SHELL_TOOLS,
    command_arg: str = "command",
) -> Callable[[str, dict[str, Any]], InverseSpec | None]:
    """Build a classifier the reversal engine can consult for shell tools.

    Returns ``None`` for anything that is not a shell tool, which leaves the
    engine's answer unchanged.

    It returns an :class:`InverseSpec`, not a posture, and that is what keeps it
    honest. A spec refuses to construct with an undoable kind and no undo path —
    "kind=reversible requires an inverse_tool or steps" — so this cannot claim a
    local write is recoverable while having nothing to run. The rule below is
    enforced by the type rather than remembered.

    Why a local write stays UNKNOWN
    -------------------------------
    ``rm -rf build/`` is recoverable *from a snapshot of the working tree*. The
    snapshot is the inverse, and this seam cannot supply one: it returns a
    posture, and the undo path comes from an :class:`InverseSpec` that by
    definition does not exist for a tool the registry has never heard of.

    An earlier version took a ``snapshots=True`` flag meaning "assume one will be
    taken", and produced exactly that failure. Returning a spec makes the same
    mistake impossible to write down.

    Getting a local write to REVERSIBLE honestly means giving this a snapshot
    mechanism to name — an inverse tool and the fields to capture — at which
    point the spec is constructible and the claim is backed by something that
    runs.

    That leaves this worth wiring anyway. It moves ``ls`` out of UNKNOWN — which
    ranks below IRREVERSIBLE — and turns ``git push --force`` from an
    unclassified thing into a known one-way door, which is a different
    conversation with a policy.
    """

    def classify_command(tool: str, args: dict[str, Any]) -> InverseSpec | None:
        if tool not in shell_tools:
            return None
        command = args.get(command_arg)
        if not isinstance(command, str) or not command.strip():
            return None
        reach = classify(command, root).reach
        if reach is Reach.READ_ONLY:
            return InverseSpec(tool=tool, kind=Reversibility.IDEMPOTENT,
                               notes="read-only shell command: nothing to undo")
        if reach is Reach.ESCAPES:
            return InverseSpec(tool=tool, kind=Reversibility.IRREVERSIBLE,
                               notes="reaches beyond the working tree")
        # LOCAL included: see the docstring. Without a snapshot mechanism to name
        # there is no inverse, and UNKNOWN is the only kind that can be stated
        # without one.
        return InverseSpec(tool=tool, kind=Reversibility.UNKNOWN,
                           notes="no snapshot mechanism configured")

    return classify_command


__all__ = [
    "DEFAULT_SHELL_TOOLS",
    "ESCAPE_PATTERNS",
    "LOCAL_WRITE_COMMANDS",
    "READ_ONLY_COMMANDS",
    "READ_ONLY_SUBCOMMANDS",
    "Reach",
    "ShellVerdict",
    "classify",
    "command_classifier",
]
