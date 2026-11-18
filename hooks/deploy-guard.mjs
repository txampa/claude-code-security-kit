// deploy-guard.mjs — PreToolUse hook (Bash, PowerShell): deploy mistakes that each happened once.
//
// Every built-in rule comes from a real incident with an AI agent and a deploy CLI (October 2026):
// - `railway up` without an explicit project didn't fail: the Railway CLI (v5) created a new project and uploaded
//   the folder into it, client files included. The link a folder has is invisible to the agent, so be explicit.
// - `railway ssh config` writes an SSH alias that ignores --environment: it connected to production when the
//   agent had asked for staging.
// - `vercel git connect`, run from the wrong folder, linked a whole workspace repo to a public site.
//
// Add your own project rules in .claude/deploy-guard.json (see examples/deploy-guard.json), for things like
// "this site only goes to production through node deploy.mjs".
//
// It only looks at commands that start with the CLI (directly or through npx, bunx, pnpm dlx…), not at text that
// mentions them (grep, commit messages): quoted strings are blanked out before splitting.

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

const DENY = 'deny', ASK = 'ask';

// Blank quoted strings and redirections, then split into simple commands
function segments(cmd) {
  return cmd
    .replace(/'[^']*'|"(?:[^"\\]|\\.)*"/g, "''")
    .replace(/\d*>&\d*/g, ' ')
    .split(/[;&|\n()]+/)
    .map(s => s.trim()
      .replace(/^(\w+=\S*\s+)*/, '')                                         // FOO=bar cmd
      .replace(/^(npx|bunx|pnpx|pnpm\s+dlx|yarn\s+dlx)(\s+(-y|--yes))?\s+/, '')
      .replace(/^@railway\/cli\b/, 'railway'))
    .filter(Boolean);
}

const has = (t, short, long) => t.some(x => x === short || x === long || x.startsWith(long + '='));

function builtIn(seg) {
  const t = seg.split(/\s+/);
  const exe = t[0].toLowerCase().replace(/^.*[\\/](?=[^\\/]+$)/, '').replace(/\.(exe|cmd|ps1)$/, '');
  if (t.includes('--help') || t.includes('-h')) return null;

  if (exe === 'railway') {
    if (t[1] === 'up') {
      if (t.includes('--new')) return [DENY, '`railway up --new` creates a new project even if the folder is linked',
        'Deploy to the project that already exists with --project <id> --environment <env> --service <service>.'];
      const missing = [['-p', '--project'], ['-e', '--environment'], ['-s', '--service']]
        .filter(([s, l]) => !has(t, s, l)).map(([, l]) => l);
      if (missing.length) return [DENY, `\`railway up\` without ${missing.join(', ')}: what the folder is linked to is invisible, and the CLI may create what's missing and upload the folder there`,
        'Say exactly where it goes: railway up --project <id> --environment <env> --service <service>.'];
    }
    if (t[1] === 'ssh' && t[2] === 'config') return [DENY, '`railway ssh config` writes an SSH alias that ignores --environment and can land in production',
      'Use railway ssh --service <s> --environment <env> and check $RAILWAY_ENVIRONMENT_NAME before writing anything.'];
    if (t[1] === 'volume' && t[2] === 'delete') return [ASK, 'deleting a Railway volume also deletes its backups', null];
    if (t[1] === 'down') return [ASK, '`railway down` removes the latest deployment', null];
  }

  if (exe === 'vercel') {
    if (t[1] === 'git' && t[2] === 'connect') return [DENY, '`vercel git connect` links whatever repo the current folder is in, and that may be a much bigger repo than the site',
      'If a repo really has to be connected, tell the user which one and let them do it in the Vercel dashboard.'];
    if (t[1] === 'remove' || t[1] === 'rm') return [ASK, '`vercel remove` deletes deployments or a whole project', null];
  }
  return null;
}

// Project rules: [{ when?, command, decision: "deny"|"ask", reason, instead? }]
//   when    — regex tested against the raw command and the session cwd (e.g. the folder of one site)
//   command — regex tested against each simple command, after npx & co. are stripped
function projectRules(input) {
  const dir = process.env.CLAUDE_PROJECT_DIR || input?.cwd;
  const file = dir && join(dir, '.claude', 'deploy-guard.json');
  if (!file || !existsSync(file)) return [];
  const rules = JSON.parse(readFileSync(file, 'utf8')).rules;   // a broken file throws: see main()
  return compile(rules);
}

// Validates the rules and compiles their regexes once; throws on anything wrong
export function compile(rules) {
  if (!Array.isArray(rules)) throw new Error('"rules" must be an array');
  return rules.map((r, i) => {
    if (typeof r?.command !== 'string') throw new Error(`rule ${i}: "command" (a regex) is required`);
    if (r.decision && r.decision !== DENY && r.decision !== ASK) throw new Error(`rule ${i}: "decision" must be "deny" or "ask"`);
    return { ...r, whenRe: r.when ? new RegExp(r.when, 'i') : null, commandRe: new RegExp(r.command, 'i') };
  });
}

// Returns [decision, reason, instead] or null. `rules` comes from compile().
export function check(cmd, cwd = '', rules = []) {
  if (typeof cmd !== 'string' || !cmd) return null;
  const segs = segments(cmd);
  for (const seg of segs) {
    const hit = builtIn(seg);
    if (hit) return hit;
  }
  for (const r of rules) {
    if (r.whenRe && !(r.whenRe.test(cmd) || r.whenRe.test(cwd))) continue;
    if (segs.some(s => r.commandRe.test(s)))
      return [r.decision === ASK ? ASK : DENY, r.reason || 'a project deploy rule matched', r.instead || null];
  }
  return null;
}

function main() {
  let input, rules;
  try {
    input = JSON.parse(readFileSync(0, 'utf8'));
    rules = projectRules(input);
  } catch (e) {
    // Guardrail: a broken input or rules file must not switch the guard off without anyone noticing
    process.stderr.write(`deploy-guard: ${e.message}. Blocking until it's fixed (check .claude/deploy-guard.json).\n`);
    process.exit(2);
  }
  const hit = check(input?.tool_input?.command, input?.cwd ?? '', rules);
  if (!hit) process.exit(0);
  const [decision, reason, instead] = hit;
  if (decision === ASK) {
    process.stdout.write(JSON.stringify({ hookSpecificOutput: {
      hookEventName: 'PreToolUse', permissionDecision: 'ask', permissionDecisionReason: `deploy-guard: ${reason}. Confirm it's intended.`,
    } }));
    process.exit(0);
  }
  process.stderr.write(`⛔ Deploy blocked: ${reason}.\n${instead ?? ''}\n`);
  process.exit(2);
}

if (!process.env.SECURITY_KIT_TEST) main();
