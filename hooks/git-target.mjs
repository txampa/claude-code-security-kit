// git-target.mjs — Tells which `git commit` / `git push` a command runs and which repo each one lands in.
//
// Used by secret-scan.sh. Input: the hook JSON on stdin. Output: one `action<TAB>dir` line per
// git commit|push, where action = commit | commit-all | push. The hook runs BEFORE the command, so the
// directory is worked out by following the command's own `cd`, `git -C` and variables: commits often
// land in nested repos, and CLAUDE_PROJECT_DIR is not necessarily the repo. commit-all means the command
// stages changes in the same run (`git add x; git commit`, -a, `-- path`): the index doesn't have them yet.

import { readFileSync } from 'fs';
import { homedir } from 'os';
import { resolve } from 'path';

const input = JSON.parse(readFileSync(0, 'utf8'));
const cmd = input?.tool_input?.command;
if (typeof cmd !== 'string') process.exit(0);

const PATH = `"[^"]*"|'[^']*'|[^\\s;&|)]+`;
const TOKEN = new RegExp(
  `(?:^|[;&|\\n(])\\s*(?:cd|pushd|Set-Location|sl)\\s+(?:-(?:Literal)?Path\\s+)?(${PATH})` +
  `|\\bgit\\b((?:\\s+-[cC]\\s+(?:${PATH}))*)\\s+(commit|push)\\b`, 'g');
const OPTION_C = new RegExp(`-C\\s+(${PATH})`, 'g');
// `R="…"; cd "$R"` is common: without resolving it, ~8% of real commit commands got blocked for nothing
const ASSIGNMENT = new RegExp(`(?:^|[;&|\\n]|\\s)\\$?([A-Za-z_]\\w*)\\s*=\\s*(${PATH})`, 'g');

const variables = { HOME: homedir() };
const expand = text => text.replace(/\$\{?([A-Za-z_]\w*)\}?/g, (all, name) => variables[name] ?? all);
const unquote = text => text.replace(/^["']|["']$/g, '');
for (const m of cmd.matchAll(ASSIGNMENT)) variables[m[1]] = expand(unquote(m[2]));

const clean = path => expand(unquote(path))
  .replace(/^\/([a-zA-Z])\//, '$1:/')
  .replace(/^~(?=[\\/]|$)/, homedir());

const stagesInSameRun = /\bgit\s+add\b/.test(cmd)
  || /\bgit\s+commit\b[^;&|\n]*(\s-[a-zA-Z]*a[a-zA-Z]*\b|\s--all\b|\s--\s)/.test(cmd);

let dir = input?.cwd || process.env.CLAUDE_PROJECT_DIR || process.cwd();
for (const m of cmd.matchAll(TOKEN)) {
  if (m[1]) {
    dir = resolve(dir, clean(m[1]));
    continue;
  }
  const option = [...(m[2] ?? '').matchAll(OPTION_C)].pop();
  const target = option ? resolve(dir, clean(option[1])) : dir;
  const action = m[3] === 'commit' && stagesInSameRun ? 'commit-all' : m[3];
  console.log(`${action}\t${target}`);
}
