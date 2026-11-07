// pre-bash-safety.mjs — PreToolUse hook (Bash): stops what can't be undone.
//
// Replaces pre-bash-safety.sh from v1, which read `command` from the root of the hook JSON (it lives in
// `tool_input.command`) and exited with 1, which doesn't block: it never stopped anything. It also
// matched substrings, so `rm -rf /` caught `rm -rf /tmp/x`. Checked against ~13,000 real agent commands,
// none was actually dangerous, so only real damage gets in here: recursive delete of the root, a drive,
// home or a system directory; writing to a disk with dd or >; mkfs; chmod -R 777 on root; fork bombs.
//
// It looks inside quotes on purpose: `ssh host '…'` and `bash -c "…"` run just the same.

import { readFileSync } from 'fs';

let cmd;
try {
  cmd = JSON.parse(readFileSync(0, 'utf8'))?.tool_input?.command;
} catch (e) {
  // Guardrail: when in doubt, block and say why.
  process.stderr.write(`pre-bash-safety: could not read the command (${e.message}); blocking it in case it is destructive.\n`);
  process.exit(2);
}
if (typeof cmd !== 'string' || !cmd) process.exit(0);

// Root, Windows drive, home and system directories; any subdirectory is fine
const ROOT = new RegExp('^(?:'
  + '/\\*?'
  + '|~/?\\*?'
  + '|\\$\\{?(?:HOME|USERPROFILE)\\}?/?\\*?'
  + '|/[a-zA-Z]/?\\*?'
  + '|[a-zA-Z]:[\\\\/]?\\*?'
  + '|(?:/[a-zA-Z]|[a-zA-Z]:)[\\\\/]Users(?:[\\\\/][^\\\\/]+)?[\\\\/]?\\*?'
  + '|/(?:bin|boot|dev|etc|home|lib|lib64|opt|root|sbin|srv|usr|var)/?\\*?'
  + ')$');
const unquote = t => t.replace(/^["']+|["']+$/g, '');

function deletesRoot(c) {
  for (const m of c.matchAll(/(?:^|[\s;&|(`"'])rm\s+([^;&|\n)]*)/g)) {
    // C:\, "C:\\" and C:/ are the same thing: compare with forward slashes
    const args = m[1].trim().split(/\s+/).map(a => unquote(a).replace(/\\+/g, '/'));
    const recursive = args.some(a => /^-[a-zA-Z]*[rR]/.test(a) || a === '--recursive');
    const target = args.find(a => a && !a.startsWith('-') && ROOT.test(a));
    if (recursive && target) return `deletes ${target} recursively`;
  }
  return null;
}

const DISK = '/dev/(?:sd[a-z]|hd[a-z]|vd[a-z]|xvd[a-z]|nvme\\d|mmcblk\\d|r?disk\\d)';
const RULES = [
  ['writes to a disk with dd', new RegExp(`\\bdd\\b[^;&|\\n]*\\bof=["']?(?:${DISK}|\\\\\\\\\\.\\\\PhysicalDrive)`, 'i')],
  ['redirects output to a disk', new RegExp(`>\\s*["']?${DISK}`)],
  ['formats a filesystem', /(?:^|[;&|(\n`"']|\bsudo)\s*mkfs(?:\.\w+)?\s/],
  ['opens root or home to 777 recursively', /\bchmod\s+(?:-[a-zA-Z-]+\s+)*-[a-zA-Z]*R[a-zA-Z]*\s+(?:-[a-zA-Z-]+\s+)*0?777\s+["']?(?:\/|~|\$\{?HOME\}?)\/?["']?(?=[\s;&|)]|$)/],
  ['is a fork bomb', /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/],
];

const reason = deletesRoot(cmd) ?? RULES.find(([, re]) => re.test(cmd))?.[0];
if (!reason) process.exit(0);

process.stderr.write(
  `⛔ Blocked: this command ${reason}, and that can't be undone.\n` +
  `If it is really needed, explain why to the user and let them run it by hand in their own terminal. Don't look for another way around.\n`);
process.exit(2);
