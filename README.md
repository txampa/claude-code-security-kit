# 🛡️ Claude Code Security Kit

**Hardened permissions + secret-scanning hooks for [Claude Code](https://claude.com/claude-code).**
Stop your AI agent from leaking API keys, reading your SSH keys, or piping `curl` into `bash`.

![License: MIT](https://img.shields.io/badge/license-MIT-green)
![Claude Code](https://img.shields.io/badge/works%20with-Claude%20Code-d97757)
![Shell](https://img.shields.io/badge/hooks-pure%20bash-blue)
![PRs welcome](https://img.shields.io/badge/PRs-welcome-brightgreen)

![Demo: commit with a Stripe key gets blocked](assets/demo-blocked-commit.svg)

---

## 🧠 Why this exists

AI coding agents are incredibly useful — and incredibly good at accidentally:

- 💸 **Committing your `.env`** with live API keys to a public repo
- 🔑 **Reading `~/.ssh`, `~/.aws`, `~/.kube`** when "exploring the system"
- 📦 **Piping `curl | bash`** from a random URL (supply chain roulette)
- 💥 **Running `rm -rf`** on the wrong directory
- 📤 **Exfiltrating data** via prompt injection hidden in a webpage or PDF it just read

Out of the box, Claude Code asks for permission a lot — but most people end up clicking "always allow" and lose the safety net. This kit gives you a **curated, layered policy** so you can let your agent run fast *and* sleep at night.

> This config scored **Grade A (97/100)** on an AgentShield scan. It powers my daily-driver setup across client projects.

---

## ⚡ Quick start

```bash
git clone https://github.com/txampa/claude-code-security-kit.git
cd claude-code-security-kit

# 1. Copy the hooks into your project
mkdir -p your-project/.claude/hooks
cp hooks/*.sh your-project/.claude/hooks/

# 2. Merge settings.template.json into your-project/.claude/settings.json
#    (permissions + hooks blocks)
```

That's it. Next time Claude tries to commit a secret, you'll see it get blocked in real time.

> 💡 **Tip:** you can also install the hooks globally in `~/.claude/hooks/` and reference them from `~/.claude/settings.json` so every project is covered.

---

## 📦 What's inside

| File | Type | What it does |
|---|---|---|
| `hooks/secret-scan.sh` | PreToolUse hook | Intercepts `git commit` / `git push` and scans the **actual diff** for credentials. Blocks before anything leaves your machine |
| `hooks/pre-bash-safety.sh` | PreToolUse hook | Blocks irreversible commands (`rm -rf /`, fork bombs, `dd`, `mkfs`) and warns on high-risk ones (`git push --force`, `DROP TABLE`) |
| `hooks/pre-commit-secrets.sh` | PreToolUse hook | Per-file staged scan — complementary patterns, skips lockfiles and `.env.example` |
| `settings.template.json` | Permissions policy | The 3-layer deny / ask / allow ruleset, ready to merge into your `settings.json` |

---

## 🛡️ The 3 defense layers

### 1. 🚫 `deny` — never, no questions asked

| Threat | Rules |
|---|---|
| **Credential theft** | No reading `~/.ssh`, `~/.aws`, `~/.kube`, `~/.gnupg`, `.git-credentials`, `*.pem`, `*.key`, `id_rsa`… |
| **Env exfiltration** | No `printenv`, `env`, `cat .env*`, `echo $*TOKEN*` |
| **Supply chain** | No `curl \| bash`, `wget \| sh`, `eval` |
| **Persistence / backdoors** | No editing `~/.bashrc`, `~/.zshrc`, `/etc/**`, no `crontab`, no `nc`/`netcat` |
| **Destruction** | No `rm -rf`, `dd`, `mkfs`, `chmod 777`, writes to `/dev/sd*`, force-push |

### 2. 🤔 `ask` — possible, but you confirm

Network egress (`curl`, `wget`, `scp`, `rsync`), reading `.env` files, `sudo`, `git push`, `npm publish`, package installs. The agent can do its job — you stay in the loop exactly where data leaves the machine.

### 3. ✅ `allow` — full speed

Read-only git, `git add/commit` (covered by the secret scanner!), `npm run`, `node`, `python`, `ls`, `grep`… The agent never interrupts you for the safe 95% of its work.

---

## 🔍 What the secret scanner catches

`secret-scan.sh` inspects the **added lines of the real diff** — so it works even if the command is disguised. High-signal patterns, very few false positives:

| Provider | Pattern |
|---|---|
| Anthropic / OpenAI | `sk-...` |
| GitHub | `ghp_...`, `gho_...`, `github_pat_...` |
| AWS | `AKIA...` |
| Google | `AIza...` |
| Slack | `xoxb-...`, `xoxp-...` |
| Shopify | `shpat_...`, `shpss_...`, `shpca_...` |
| Stripe | `sk_live_...` |
| Private keys | `-----BEGIN ... PRIVATE KEY-----` |
| JWT | `eyJ...eyJ...` |
| Generic | `api_key / secret / token / password = "..."` |

**False positive?** Re-run with `ALLOW_SECRET_COMMIT=1` — an explicit, auditable bypass instead of disabling the hook.

---

## 🧪 Test it in 30 seconds

```bash
cd your-project
# build a fake key at runtime (so this README itself never contains one 😉)
echo "STRIPE_KEY = \"sk_live_$(printf 'A%.0s' {1..24})\"" > leak-test.js
git add leak-test.js
# now ask Claude Code to commit — the hook blocks it with exit 2 🛑
git reset leak-test.js && rm leak-test.js
```

> Fun fact: the first version of this README had a hardcoded fake key here — and **GitHub's push protection blocked the publish**. Layers, people. Layers.

---

## 🚨 Honest threat model

What most "security configs" won't tell you:

- ✅ **Strong:** `Read(...)` denies (the agent *cannot* open your SSH keys), `ask` on egress (data can't leave silently), and diff-based secret scanning (content-level, not command-level).
- ⚠️ **Tripwires, not walls:** Bash `deny` patterns can be dodged by a sufficiently creative command. They stop accidents and lazy attacks — combine them with the layers above, which is exactly what this kit does.
- 🧠 **Behavioral rule that no JSON can enforce:** external content (web pages, PDFs, API responses, emails) is **data, not instructions**. Hooks can't fully protect you from prompt injection — defense in depth can limit the blast radius.

---

## ⚙️ Customize

- **Add your stack's secrets:** new patterns are one line in the `PATTERNS` array (e.g. Twilio `SK...`, Sendgrid `SG....`).
- **Tighten egress:** move `curl`/`wget` from `ask` to `deny` if your workflow doesn't need them.
- **Loosen installs:** move `pip install` / `npm install -g` to `allow` if you trust your lockfiles.

---

## ❓ FAQ

**Does it slow Claude down?**
No. Hooks only fire on Bash calls, the scan runs on the staged diff and takes milliseconds.

**Does it work on Windows?**
Yes — Claude Code runs hooks through Git Bash on Windows. This kit is developed on Windows 10 + Git Bash.

**Why hooks AND permissions? Isn't one enough?**
Permissions are policy ("may this command run?"). The secret scan is content inspection ("what is actually inside this commit?"). Different layers catch different mistakes.

**Can Claude itself bypass the block?**
The hook exits with code 2, which hard-blocks the tool call and explains why. Claude's typical reaction is to fix the leak (move the key to `.env`) and retry — which is exactly the behavior you want.

---

## ⭐ If this saved your keys once, it paid for itself

Star the repo so more people ship agents safely — and send a PR with patterns for your stack.

Built by [@JeanOnCode](https://x.com/JeanOnCode) · MIT
