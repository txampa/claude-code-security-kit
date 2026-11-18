// node tests/run.mjs — checks every hook against commands that must and must not trigger it,
// then runs each hook once for real (stdin JSON → exit code / JSON output), as Claude Code does.
import { spawnSync } from 'child_process';
import { fileURLToPath, pathToFileURL } from 'url';
import { dirname, join } from 'path';

process.env.SECURITY_KIT_TEST = '1';
const hooks = join(dirname(fileURLToPath(import.meta.url)), '..', 'hooks');
const load = f => import(pathToFileURL(join(hooks, f)).href);
const safety = await load('pre-bash-safety.mjs');
const deploy = await load('deploy-guard.mjs');
const db = await load('db-guard.mjs');

let failed = 0, total = 0;
function expect(name, got, want) {
  total++;
  const ok = want ? Boolean(got) : !got;
  if (!ok) { failed++; console.log(`✗ ${name}\n    got: ${JSON.stringify(got)}`); }
}

// --- pre-bash-safety: must block
for (const c of [
  'rm -rf /', 'rm -rf ~', 'rm -rf $HOME', 'sudo rm -rf /*', 'rm -rf /c', 'rm -rf C:\\', 'rm -fr "C:/"',
  'ssh box "rm -rf /"', 'dd if=/dev/zero of=/dev/sda', 'mkfs.ext4 /dev/sdb1', 'chmod -R 777 /', ':(){ :|:& };:',
  // PowerShell / cmd
  'Remove-Item -Recurse -Force C:\\', 'Remove-Item C:\\ -Recurse', 'rm -r -fo C:\\', 'ri -Recurse $env:USERPROFILE',
  'Remove-Item -Path "C:\\Program Files" -Recurse -Force', 'Remove-Item -rec -fo C:\\Users\\someone', 'Remove-Item -Recurse:$true C:\\Windows',
  'rd /s /q C:\\', 'cmd /c "rd /s /q C:\\"', 'del /s /q C:\\*', 'rmdir /S D:\\',
  'Format-Volume -DriveLetter D', 'Clear-Disk -Number 1 -RemoveData', 'format D: /q',
  'vssadmin delete shadows /all /quiet', 'wmic shadowcopy delete', 'Get-CimInstance Win32_ShadowCopy | Remove-CimInstance',
  'wbadmin delete catalog -quiet', 'bcdedit /set {default} recoveryenabled No',
]) expect(`safety blocks: ${c}`, safety.check(c), true);

// --- pre-bash-safety: must let through
for (const c of [
  'rm -rf node_modules', 'rm -rf /tmp/build', 'rm -rf ~/proj/dist', 'rm -f /', 'rm -rf C:/Users/me/proj/out',
  'Remove-Item -Recurse -Force .\\dist', 'Remove-Item -Force C:\\', 'Remove-Item C:\\Users\\me\\proj\\out -Recurse -Force',
  'Remove-Item -Recurse -Force "$env:TEMP\\x"', 'Remove-Item -Force -Path C:\\temp\\a.txt', 'rd /s /q .\\build', 'del /q C:\\temp\\x.log',
  'Get-ChildItem | Format-Table', 'Get-Disk', 'vssadmin list shadows', 'Get-CimInstance Win32_ShadowCopy', 'bcdedit /enum',
  'git log --format "%h %s"', 'npm run format', 'dd if=a.img of=b.img',
]) expect(`safety allows: ${c}`, safety.check(c), false);

// --- deploy-guard
const rules = deploy.compile([{ when: 'my-landing', command: '^vercel\\b.*(--prod\\b|\\bpromote\\b)', decision: 'deny', reason: 'site deploys with deploy.mjs' }]);
const d = (c, cwd = '') => deploy.check(c, cwd, rules);
for (const [c, want] of [
  ['railway up', 'deny'], ['railway up --detach', 'deny'], ['npx @railway/cli up', 'deny'], ['railway up --project p --environment production', 'deny'],
  ['railway up --new', 'deny'], ['railway ssh config', 'deny'], ['railway volume delete --volume v', 'ask'], ['railway down', 'ask'],
  ['vercel git connect', 'deny'], ['npx vercel rm my-app', 'ask'], ['cd my-landing && npx vercel --prod --yes', 'deny'],
  ['& railway up', 'deny'], ['railway.exe up', 'deny'],
]) { const got = d(c); total++; if (got?.[0] !== want) { failed++; console.log(`✗ deploy ${want}: ${c}\n    got: ${JSON.stringify(got)}`); } }
for (const c of [
  'railway up --project p --environment production --service web --detach', 'railway up -p p -e staging -s web',
  'railway ssh --service web --environment staging', 'railway logs', 'railway up --help', 'vercel --prod',
  'git commit -m "railway up without flags"', 'grep -rn "vercel git connect" docs', 'echo railway up',
]) expect(`deploy allows: ${c}`, d(c), false);
expect('deploy custom rule only in its folder', d('npx vercel --prod', 'C:/work/my-landing'), true);
total++; try { deploy.compile([{ command: '(' }]); failed++; console.log('✗ compile should reject a broken regex'); } catch {}

// --- db-guard
for (const c of [
  'psql "$DATABASE_URL" -c "DROP TABLE users"', 'psql -c "TRUNCATE bookings"', "psql -c 'DELETE FROM users'",
  'psql -c "DELETE FROM users;"', 'psql -c "UPDATE users SET admin = true"', 'sqlite3 app.db "DROP TABLE x"',
  'mysql -e "DROP DATABASE shop"', 'redis-cli FLUSHALL', 'mongosh --eval "db.dropDatabase()"', 'dropdb mydb',
  'npx prisma migrate reset --force', 'npx prisma db push --force-reset', 'docker exec db psql -U app -c "DROP SCHEMA public CASCADE"',
]) expect(`db asks: ${c}`, db.check(c), true);
for (const c of [
  'psql -c "SELECT * FROM users"', 'psql -c "DELETE FROM users WHERE id = 3"', 'psql -c "UPDATE users SET a = 1 WHERE id = 2"',
  'grep -rn "DROP TABLE" migrations/', 'git commit -m "drop table users"', 'redis-cli GET key', 'npx prisma migrate dev',
  'psql -f migrations/001.sql',
]) expect(`db allows: ${c}`, db.check(c), false);

// --- end to end: each hook as Claude Code runs it
const run = (hook, tool, command, env = {}) => spawnSync(process.execPath, [join(hooks, hook)], {
  input: JSON.stringify({ hook_event_name: 'PreToolUse', tool_name: tool, tool_input: { command }, cwd: '.' }),
  env: { ...process.env, SECURITY_KIT_TEST: '', CLAUDE_PROJECT_DIR: '', ...env }, encoding: 'utf8',
});
const e2e = [
  ['pre-bash-safety.mjs', 'PowerShell', 'Remove-Item -Recurse -Force C:\\', r => r.status === 2 && /Blocked/.test(r.stderr)],
  ['pre-bash-safety.mjs', 'Bash', 'ls -la', r => r.status === 0 && !r.stdout],
  ['deploy-guard.mjs', 'Bash', 'railway up', r => r.status === 2 && /Deploy blocked/.test(r.stderr)],
  ['deploy-guard.mjs', 'Bash', 'railway down', r => r.status === 0 && JSON.parse(r.stdout).hookSpecificOutput.permissionDecision === 'ask'],
  ['db-guard.mjs', 'PowerShell', 'psql -c "DROP TABLE x"', r => r.status === 0 && JSON.parse(r.stdout).hookSpecificOutput.permissionDecision === 'ask'],
  ['db-guard.mjs', 'Bash', 'psql -c "SELECT 1"', r => r.status === 0 && !r.stdout],
];
for (const [hook, tool, cmd, ok] of e2e) {
  total++;
  const r = run(hook, tool, cmd);
  let pass = false;
  try { pass = ok(r); } catch {}
  if (!pass) { failed++; console.log(`✗ e2e ${hook} (${tool}): ${cmd}\n    status ${r.status} stdout ${r.stdout} stderr ${r.stderr}`); }
}
total++;
const bad = spawnSync(process.execPath, [join(hooks, 'pre-bash-safety.mjs')], { input: 'not json', env: { ...process.env, SECURITY_KIT_TEST: '' }, encoding: 'utf8' });
if (bad.status !== 2) { failed++; console.log('✗ unreadable input must block'); }

console.log(`\n${total - failed}/${total} passed`);
process.exit(failed ? 1 : 0);
