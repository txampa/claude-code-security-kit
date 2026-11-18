// db-guard.mjs — PreToolUse hook (Bash, PowerShell): asks you before a destructive database command.
//
// It doesn't block: dropping a local test database is sometimes exactly what you want. It turns the command
// into a permission prompt, so the agent can't run it on its own even if the database client is allowed.
//
// It only fires when the command runs a database client (psql, mysql, sqlite3, sqlcmd, mongosh, redis-cli…)
// or a tool that wipes a database (dropdb, prisma migrate reset…). `grep -r "DROP TABLE" .` is left alone.
// Limit: SQL inside a file (`psql -f migration.sql`) is not read.

import { readFileSync } from 'fs';

const CLIENT = /(?:^|[\s;&|(`"'/\\])(?:psql|mysql|mariadb|sqlite3|sqlcmd|duckdb|clickhouse(?:-client)?|mongosh|mongo|redis-cli)(?:\.exe)?(?=[\s"']|$)/i;

const TOOLS = [
  ['drops a PostgreSQL database', /(?:^|[\s;&|(])dropdb(?:\.exe)?\s/i],
  ['drops a MySQL database', /\bmysqladmin(?:\.exe)?\b[^;&|\n]*\bdrop\b/i],
  ['resets the database (drops all data)', /\bprisma\s+migrate\s+reset\b|\bprisma\s+db\s+push\b[^;&|\n]*--force-reset\b/i],
];

const STATEMENTS = [
  ['drops a table, view, schema or database', /\bDROP\s+(?:TABLE|VIEW|SCHEMA|DATABASE)\b/i],
  ['truncates a table', /\bTRUNCATE\s+(?:TABLE\s+)?[\w."`[\]]+/i],
  ['deletes every row of a table (DELETE without WHERE)', /\bDELETE\s+FROM\s+[\w."`[\]]+(?:\s+(?:AS\s+)?\w+)?\s*(?=;|$|["'])/i],
  ['wipes a Redis database', /\bFLUSH(?:ALL|DB)\b/i],
  ['drops a MongoDB database or collection', /\.dropDatabase\s*\(|\.drop\s*\(\s*\)/],
];

// UPDATE … SET … with no WHERE before the end of the statement
function updateWithoutWhere(c) {
  for (const m of c.matchAll(/\bUPDATE\s+[\w."`[\]]+\s+SET\b([^;]*)/gi)) {
    if (!/\bWHERE\b/i.test(m[1])) return 'updates every row of a table (UPDATE without WHERE)';
  }
  return null;
}

// Returns what the command would do, or null
export function check(cmd) {
  if (typeof cmd !== 'string' || !cmd) return null;
  const tool = TOOLS.find(([, re]) => re.test(cmd));
  if (tool) return tool[0];
  if (!CLIENT.test(cmd)) return null;
  return STATEMENTS.find(([, re]) => re.test(cmd))?.[0] ?? updateWithoutWhere(cmd);
}

function main() {
  let cmd;
  try {
    cmd = JSON.parse(readFileSync(0, 'utf8'))?.tool_input?.command;
  } catch (e) {
    process.stderr.write(`db-guard: could not read the command (${e.message}); blocking it in case it is destructive.\n`);
    process.exit(2);
  }
  const what = check(cmd);
  if (!what) process.exit(0);
  process.stdout.write(JSON.stringify({ hookSpecificOutput: {
    hookEventName: 'PreToolUse',
    permissionDecision: 'ask',
    permissionDecisionReason: `db-guard: this command ${what}. Check which database it points to before allowing it.`,
  } }));
  process.exit(0);
}

if (!process.env.SECURITY_KIT_TEST) main();
