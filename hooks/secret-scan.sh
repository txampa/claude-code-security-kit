#!/usr/bin/env bash
# secret-scan.sh — PreToolUse anti-secrets hook for Claude Code.
# Intercepts `git commit` and `git push`, scans what is about to be pushed
# for tokens/credentials and BLOCKS (exit 2) if it finds any.
#
# Philosophy: protection "by structure", not a Bash tripwire. Even if the
# command is disguised, what matters is the CONTENT entering git.
#
# Bypass (only for a confirmed false positive): ALLOW_SECRET_COMMIT=1
#
# Exit codes: exit 0 = allow | exit 2 = block and show the reason to Claude.

set -uo pipefail

# --- Read the command about to run (stdin = hook JSON) ---
INPUT="$(cat 2>/dev/null || true)"
CMD="$(printf '%s' "$INPUT" | grep -oE '"command"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | sed -E 's/.*:[[:space:]]*"(.*)"/\1/')"

# Only act on git commit / git push. Everything else passes.
case "$CMD" in
  *"git commit"*|*"git push"*) : ;;
  *) exit 0 ;;
esac

# Explicit manual bypass
if [ "${ALLOW_SECRET_COMMIT:-0}" = "1" ]; then
  exit 0
fi

# Move into the repo
cd "${CLAUDE_PROJECT_DIR:-.}" 2>/dev/null || exit 0
command -v git >/dev/null 2>&1 || exit 0

# --- Get the content to inspect ---
# commit  -> staged changes (what will enter the commit)
# push    -> local commits not yet pushed (full patch)
DIFF=""
case "$CMD" in
  *"git push"*)
    DIFF="$(git log -p --branches --not --remotes 2>/dev/null || true)"
    [ -z "$DIFF" ] && DIFF="$(git diff -p HEAD~1..HEAD 2>/dev/null || true)"
    ;;
  *)
    DIFF="$(git diff --cached 2>/dev/null || true)"
    ;;
esac
[ -z "$DIFF" ] && exit 0

# Only added lines matter (they start with +)
ADDED="$(printf '%s\n' "$DIFF" | grep -E '^\+' || true)"
[ -z "$ADDED" ] && exit 0

# --- High-signal secret patterns (few false positives) ---
# Each entry: label|regex
PATTERNS=(
  "API key (Anthropic/OpenAI)|sk-[A-Za-z0-9_-]{20,}"
  "GitHub token|gh[pousr]_[A-Za-z0-9]{30,}"
  "GitHub fine-grained PAT|github_pat_[A-Za-z0-9_]{40,}"
  "AWS Access Key|AKIA[0-9A-Z]{16}"
  "Google API key|AIza[0-9A-Za-z_-]{30,}"
  "Slack token|xox[baprs]-[A-Za-z0-9-]{10,}"
  "Shopify access token|shp(at|ss|ca|pa)_[a-fA-F0-9]{32}"
  "Stripe secret key|sk_live_[A-Za-z0-9]{20,}"
  "PEM private key|-----BEGIN [A-Z ]*PRIVATE KEY-----"
  "JWT|eyJ[A-Za-z0-9_-]{10,}\\.eyJ[A-Za-z0-9_-]{10,}"
  "Generic assigned token|(api[_-]?key|secret|token|passwd|password)[\"'[:space:]]*[:=][\"'[:space:]]*[A-Za-z0-9_\\-]{16,}"
)

HITS=""
for entry in "${PATTERNS[@]}"; do
  label="${entry%%|*}"
  regex="${entry#*|}"
  match="$(printf '%s\n' "$ADDED" | grep -iEn -e "$regex" | head -3 || true)"
  if [ -n "$match" ]; then
    HITS="${HITS}\n  ⛔ ${label}:\n$(printf '%s\n' "$match" | sed 's/^/      /')\n"
  fi
done

if [ -n "$HITS" ]; then
  {
    echo "🛑 BLOCKED: possible secret/credential in what you are about to push to git."
    echo -e "$HITS"
    echo "What to do:"
    echo "  1. Remove the secret from the code → use an environment variable or .env (gitignored)."
    echo "  2. If it is ALREADY committed, rewrite history before pushing."
    echo "  3. Confirmed false positive → retry with: ALLOW_SECRET_COMMIT=1"
  } >&2
  exit 2
fi

exit 0
