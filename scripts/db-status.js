import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import pg from "pg";

const { Pool } = pg;
const connectionString = process.env.REALTIME_DATABASE_URL;
if (!connectionString) {
  console.error("REALTIME_DATABASE_URL is required");
  process.exit(2);
}

const migrationsDir = path.resolve("migrations");
const pool = new Pool({ connectionString });

try {
  const names = (await fs.readdir(migrationsDir))
    .filter(name => /^\d+_.+\.sql$/.test(name))
    .sort();

  const table = await pool.query(
    "SELECT to_regclass('realtime.schema_migrations') AS migration_table",
  );
  const applied = new Map();
  if (table.rows[0]?.migration_table) {
    const rows = await pool.query(
      "SELECT name, checksum, applied_at FROM realtime.schema_migrations ORDER BY name",
    );
    for (const row of rows.rows) applied.set(row.name, row);
  }

  let pending = 0;
  for (const name of names) {
    const sql = await fs.readFile(path.join(migrationsDir, name), "utf8");
    const checksum = crypto.createHash("sha256").update(sql).digest("hex");
    const row = applied.get(name);
    if (!row) {
      pending += 1;
      console.log(`PENDING ${name}`);
    } else if (row.checksum !== checksum) {
      console.log(`MISMATCH ${name}`);
      process.exitCode = 1;
    } else {
      console.log(`APPLIED ${name} ${new Date(row.applied_at).toISOString()}`);
    }
  }
  console.log(`SUMMARY total=${names.length} applied=${names.length - pending} pending=${pending}`);
} finally {
  await pool.end();
}
