#!/usr/bin/env bash
# secret-scan.sh — PreToolUse anti-secrets hook for Claude Code.
# Intercepts `git commit` and `git push`, scans what is about to be committed or pushed
# for tokens/credentials and BLOCKS (exit 2) if it finds any.
#
# Philosophy: protection "by structure", not a Bash tripwire. Even if the
# command is disguised, what matters is the CONTENT entering git.
#
# Bypass (only for a false positive the user has confirmed): ALLOW_SECRET_COMMIT=1,
# in the environment or in front of the command.
#
# Needs git and node (git-target.mjs lives next to this file).
# Exit codes: exit 0 = allow | exit 2 = block and show the reason to Claude.

set -uo pipefail

# --- Read the command about to run (stdin = hook JSON) ---
INPUT="$(cat 2>/dev/null || true)"

# Most commands never touch git: no need to start node for them.
case "$INPUT" in
  *git*) : ;;
  *) exit 0 ;;
esac

# Explicit manual bypass
if [ "${ALLOW_SECRET_COMMIT:-0}" = "1" ]; then
  exit 0
fi
case "$INPUT" in
  *ALLOW_SECRET_COMMIT=1*) exit 0 ;;
esac

command -v git >/dev/null 2>&1 || exit 0

# Which commits and pushes the command runs, and in which repo. Up to v1 the command was pulled out
# with grep, which stopped at the first escaped quote, and the scan ran in CLAUDE_PROJECT_DIR: neither
# `cd "…" && git commit` nor nested repos were ever scanned.
HOOKS="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if ! TARGETS="$(printf '%s' "$INPUT" | node "$HOOKS/git-target.mjs")"; then
  echo "secret-scan: could not read the command; blocking it in case it uploads a secret." >&2
  exit 2
fi
[ -z "$TARGETS" ] && exit 0

# --- What to inspect ---
# commit      -> staged changes (what will enter the commit)
# commit-all  -> the command stages in the same run: the index doesn't have it yet, so compare with HEAD.
#                A brand-new untracked file doesn't show up here; the push scan catches it.
# push        -> local commits not pushed yet (full patch)
ADDED=""
while IFS=$'\t' read -r ACTION DIR; do
  if ! cd "$DIR" 2>/dev/null; then
    # A literal path that doesn't exist here is not a local repo: a command over ssh, or quoted text
    case "$DIR" in
      *'$'*)
        echo "🛑 BLOCKED: can't tell which repo this git ${ACTION%-all} lands in (dir: $DIR). Use a literal path with cd or git -C." >&2
        exit 2
        ;;
      *) continue ;;
    esac
  fi
  git rev-parse --git-dir >/dev/null 2>&1 || continue
  case "$ACTION" in
    push)
      DIFF="$(git log -p --branches --not --remotes 2>/dev/null || true)"
      [ -z "$DIFF" ] && DIFF="$(git diff -p HEAD~1..HEAD 2>/dev/null || true)"
      ;;
    commit-all)
      DIFF="$(git diff HEAD 2>/dev/null || git diff --cached 2>/dev/null || true)"
      ;;
    *)
      DIFF="$(git diff --cached 2>/dev/null || true)"
      ;;
  esac
  # Only added lines matter (they start with +)
  ADDED="${ADDED}$(printf '%s\n' "$DIFF" | grep -E '^\+' || true)"$'\n'
done <<< "$TARGETS"
[ -z "${ADDED//[[:space:]]/}" ] && exit 0

# --- High-signal secret patterns (few false positives) ---
# Each entry: label|regex
PATTERNS=(
  "API key (Anthropic/OpenAI)|(^|[^A-Za-z0-9])sk-[A-Za-z0-9_-]{20,}"
  "Google OAuth client secret|GOCSPX-[A-Za-z0-9_-]{20,}"
  "LangSmith API key|lsv2_(pt|sk)_[A-Za-z0-9_]{20,}"
  "GitHub token|gh[pousr]_[A-Za-z0-9]{30,}"
  "GitHub fine-grained PAT|github_pat_[A-Za-z0-9_]{40,}"
  "AWS Access Key|AKIA[0-9A-Z]{16}"
  "Google API key|AIza[0-9A-Za-z_-]{30,}"
  "Slack token|xox[baprs]-[A-Za-z0-9-]{10,}"
  "Shopify access token|shp(at|ss|ca|pa)_[a-fA-F0-9]{32}"
  "Stripe secret key|sk_live_[A-Za-z0-9]{20,}"
  "PEM private key|-----BEGIN [A-Z ]*PRIVATE KEY-----"
  "JWT|eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}"
  # Literals only: quoted, or NAME=value .env style. Otherwise `token = getSessionToken()` fired
  "Generic assigned token|(api[_-]?key|secret|token|passwd|password)[\"']?[[:space:]]*[:=][[:space:]]*[\"'][A-Za-z0-9_\\-]{16,}[\"']|^\+[[:space:]]*(export[[:space:]]+)?[A-Z0-9_]*(API_?KEY|SECRET|TOKEN|PASSWD|PASSWORD)=[A-Za-z0-9_\\-]{16,}[[:space:]]*$"
)

# Test fixtures (fake passwords in tests/, *.test.*, *.spec.*) fired the generic pattern on about
# 1 commit in 20 in a real project: that pattern skips test files. The exact-shape ones still check them.
NO_TESTS="$(printf '%s\n' "$ADDED" | awk '/^\+\+\+ /{t = ($0 ~ /(^|\/)(tests?|__tests__|e2e)\/|\.(test|spec)\.[a-z]+$/)} !t')"

HITS=""
for entry in "${PATTERNS[@]}"; do
  label="${entry%%|*}"
  regex="${entry#*|}"
  # Only the generic pattern ignores case: with -i, AKIA and AIza fired inside base64 data.
  # Counts only: this message ends up in the transcript, and the value must not go with it.
  case "$label" in
    "Generic"*) count="$(printf '%s\n' "$NO_TESTS" | grep -icE -e "$regex" || true)" ;;
    *) count="$(printf '%s\n' "$ADDED" | grep -cE -e "$regex" || true)" ;;
  esac
  if [ "${count:-0}" -gt 0 ]; then
    HITS="${HITS}\n  ⛔ ${label}: ${count} line(s)"
  fi
done

if [ -n "$HITS" ]; then
  {
    echo "🛑 BLOCKED: possible secret/credential in what you are about to commit or push."
    echo -e "$HITS"
    echo ""
    echo "The values are not shown on purpose: this message ends up in the transcript."
    echo "What to do:"
    echo "  1. Remove the secret from the code → use an environment variable or .env (gitignored)."
    echo "  2. If it is ALREADY committed, rewrite history before pushing."
    echo "  3. Confirmed false positive (ask the user first) → retry with ALLOW_SECRET_COMMIT=1 in front of the command."
  } >&2
  exit 2
fi

exit 0
