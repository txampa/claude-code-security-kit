// pre-bash-safety.mjs — PreToolUse hook (Bash, PowerShell): stops what can't be undone.
//
// v3 (Nov 2026): PowerShell too. On Windows, Claude Code also has a PowerShell tool, and v2 only looked at Bash,
// so `Remove-Item -Recurse -Force C:\` went straight through. It now knows Remove-Item and its aliases, cmd's
// `rd /s` and `del /s`, Format-Volume and Clear-Disk, and the two things ransomware does before encrypting:
// deleting the Volume Shadow Copies and turning off Windows recovery.
//
// v2 notes: the v1 hook read `command` from the root of the hook JSON (it lives in `tool_input.command`) and
// exited with 1, which doesn't block: it never stopped anything. It also matched substrings, so `rm -rf /`
// caught `rm -rf /tmp/x`. Only real damage gets in here: recursive delete of the root, a drive, home or a
// system directory; writing to a disk; formatting; chmod -R 777 on root; fork bombs.
//
// It looks inside quotes on purpose: `ssh host '…'`, `bash -c "…"` and `cmd /c "…"` run just the same.

import { readFileSync } from 'fs';

// Root, drive, home and system directories (paths are compared with forward slashes); any subdirectory is fine
const ROOT = new RegExp('^(?:'
  + '/\\*?'
  + '|~/?\\*?'
  + '|\\$\\{?(?:HOME|USERPROFILE)\\}?/?\\*?'
  + '|\\$env:(?:USERPROFILE|HOME|HOMEDRIVE|SystemDrive|SystemRoot|windir|ProgramFiles|ProgramData)/?\\*?'
  + '|/[a-zA-Z]/?\\*?'
  + '|[a-zA-Z]:/?\\*?'
  + '|(?:/[a-zA-Z]|[a-zA-Z]:)/Users(?:/[^/]+)?/?\\*?'
  + '|(?:/[a-zA-Z]|[a-zA-Z]:)/(?:Windows|Program Files|Program Files \\(x86\\)|ProgramData)/?\\*?'
  + '|/(?:bin|boot|dev|etc|home|lib|lib64|opt|root|sbin|srv|usr|var)/?\\*?'
  + ')$', 'i');

// Splits arguments keeping quoted paths with spaces together ("C:\Program Files")
const tokens = s => s.match(/"[^"]*"|'[^']*'|[^\s"']+/g) ?? [];
const unquote = t => t.replace(/^["']+|["']+$/g, '');

// rm (bash, or PowerShell's alias), Remove-Item and its aliases, and cmd's del/erase/rd/rmdir
const DELETE = /(?:^|[\s;&|(`"'{])(rm|Remove-Item|ri|del|erase|rd|rmdir)(?:\.exe)?\s+([^;&|\n)}]*)/gi;

function deletesRoot(c) {
  for (const m of c.matchAll(DELETE)) {
    const cmdStyle = /^(del|erase|rd|rmdir)$/i.test(m[1]);
    const args = tokens(m[2]).map(a => unquote(a).replace(/\\+/g, '/'));
    const recursive = args.some(a =>
      (/^-[a-zA-Z]{1,4}$/.test(a) && /[rR]/.test(a))           // rm -rf, -fr, -Rf (but not -Force)
      || a === '--recursive'
      || /^-r(e(c(u(r(se?)?)?)?)?)?(:\$true)?$/i.test(a)         // PowerShell -Recurse and its prefixes
      || (cmdStyle && /^\/s$/i.test(a)));                         // cmd: rd /s, del /s
    const target = args.find(a => a && !a.startsWith('-')
      && !(cmdStyle && /^\/[a-zA-Z?]$/.test(a))                   // cmd switches like /q are not paths
      && ROOT.test(a));
    if (recursive && target) return `deletes ${target} recursively`;
  }
  return null;
}

const DISK = '/dev/(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\\d|mmcblk\\d|r?disk\\d)';
const RULES = [
  ['writes to a disk with dd', new RegExp(`\\bdd\\b[^;&|\\n]*\\bof=["']?(?:${DISK}|\\\\\\\\\\.\\\\PhysicalDrive)`, 'i')],
  ['redirects output to a disk', new RegExp(`>\\s*["']?${DISK}`)],
  ['formats a filesystem', /(?:^|[;&|(\n`"']|\bsudo)\s*mkfs(?:\.\w+)?\s/],
  ['formats or wipes a disk', /\b(?:Format-Volume|Clear-Disk)\b/i],
  ['formats a drive', /(?:^|[;&|(\n`"'\s])format(?:\.com)?\s+[a-zA-Z]:/i],
  ['opens root or home to 777 recursively', /\bchmod\s+(?:-[a-zA-Z-]+\s+)*-[a-zA-Z]*R[a-zA-Z]*\s+(?:-[a-zA-Z-]+\s+)*0?777\s+["']?(?:\/|~|\$\{?HOME\}?)\/?["']?(?=[\s;&|)]|$)/],
  ['is a fork bomb', /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/],
  // What ransomware does first on Windows: no restore points, no backups, no recovery
  ['deletes the Volume Shadow Copies (restore points)', /\bvssadmin(?:\.exe)?\s+delete\s+shadows\b|\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b|Win32_ShadowCopy[\s\S]*\b(?:Remove-CimInstance|Remove-WmiObject|\.Delete\(\))/i],
  ['deletes the Windows backup catalog', /\bwbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup|backup)\b/i],
  ['turns off Windows recovery', /\bbcdedit(?:\.exe)?\b[^;&|\n]*\brecoveryenabled\s+no\b/i],
];

// Returns why the command is blocked, or null
export function check(cmd) {
  if (typeof cmd !== 'string' || !cmd) return null;
  return deletesRoot(cmd) ?? RULES.find(([, re]) => re.test(cmd))?.[0] ?? null;
}

function main() {
  let cmd;
  try {
    cmd = JSON.parse(readFileSync(0, 'utf8'))?.tool_input?.command;
  } catch (e) {
    // Guardrail: when in doubt, block and say why.
    process.stderr.write(`pre-bash-safety: could not read the command (${e.message}); blocking it in case it is destructive.\n`);
    process.exit(2);
  }
  const reason = check(cmd);
  if (!reason) process.exit(0);
  process.stderr.write(
    `⛔ Blocked: this command ${reason}, and that can't be undone.\n` +
    `If it is really needed, explain why to the user and let them run it by hand in their own terminal. Don't look for another way around.\n`);
  process.exit(2);
}

// The tests import check() without running the hook
if (!process.env.SECURITY_KIT_TEST) main();
