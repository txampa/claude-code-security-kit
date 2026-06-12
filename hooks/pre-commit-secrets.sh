#!/bin/bash
# Hook: pre-commit-secrets
# Runs before git commit commands.
# Scans staged files for API keys, tokens, and credentials.

INPUT=$(cat)
COMMAND=$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('command',''))" 2>/dev/null)

# Only trigger on git commit commands
if ! echo "$COMMAND" | grep -qE "git (commit|push)"; then
  exit 0
fi

# Get staged files
STAGED_FILES=$(git diff --cached --name-only 2>/dev/null)

if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

# Patterns to detect
SECRET_PATTERNS=(
  "sk-[a-zA-Z0-9]{20,}"                         # OpenAI API key
  "sk-ant-[a-zA-Z0-9\-]{30,}"                   # Anthropic API key
  "AKIA[0-9A-Z]{16}"                             # AWS Access Key
  "aws_secret_access_key\s*=\s*[^\s]+"           # AWS Secret
  "-----BEGIN (RSA|OPENSSH|EC) PRIVATE KEY-----" # Private keys
  "Bearer [A-Za-z0-9_\-\.]{20,}"                # Bearer tokens
  "password\s*=\s*['\"][^'\"]{6,}['\"]"          # Hardcoded passwords
  "DATABASE_URL.*:.*@"                            # DB connection strings with credentials
  "ghp_[a-zA-Z0-9]{36}"                          # GitHub personal token
)

FOUND_SECRETS=false

for file in $STAGED_FILES; do
  # Skip binary files, lock files, .env.example
  [[ "$file" == *".lock" ]] && continue
  [[ "$file" == *"package-lock.json" ]] && continue
  [[ "$file" == *".env.example" ]] && continue
  [[ "$file" == *".env.sample" ]] && continue

  # Skip if file doesn't exist (deleted)
  [ ! -f "$file" ] && continue

  FILE_CONTENT=$(git diff --cached -- "$file" 2>/dev/null)

  for pattern in "${SECRET_PATTERNS[@]}"; do
    if echo "$FILE_CONTENT" | grep -qE "$pattern"; then
      echo "SECRET DETECTED in '$file': matches pattern '$pattern'" >&2
      FOUND_SECRETS=true
    fi
  done
done

if [ "$FOUND_SECRETS" = true ]; then
  echo "" >&2
  echo "BLOCKED: Possible secrets detected in staged files." >&2
  echo "Options:" >&2
  echo "  1. Remove the secret and use environment variables instead" >&2
  echo "  2. Add the file to .gitignore" >&2
  echo "  3. If it's a false positive, commit manually: git commit --no-verify" >&2
  exit 1
fi

exit 0
