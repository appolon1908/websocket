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
  await pool.query("CREATE SCHEMA IF NOT EXISTS realtime");
  await pool.query(`
    CREATE TABLE IF NOT EXISTS realtime.schema_migrations (
      name TEXT PRIMARY KEY,
      checksum TEXT NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  const names = (await fs.readdir(migrationsDir))
    .filter(name => /^\d+_.+\.sql$/.test(name))
    .sort();

  const appliedResult = await pool.query(
    "SELECT name, checksum FROM realtime.schema_migrations ORDER BY name",
  );
  const applied = new Map(appliedResult.rows.map(row => [row.name, row.checksum]));

  for (const name of names) {
    const sql = await fs.readFile(path.join(migrationsDir, name), "utf8");
    const checksum = crypto.createHash("sha256").update(sql).digest("hex");
    if (applied.has(name)) {
      if (applied.get(name) !== checksum) {
        throw new Error(`migration_checksum_mismatch: ${name}`);
      }
      console.log(`SKIP ${name}`);
      continue;
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(sql);
      await client.query(
        "INSERT INTO realtime.schema_migrations(name, checksum) VALUES ($1, $2)",
        [name, checksum],
      );
      await client.query("COMMIT");
      console.log(`APPLIED ${name}`);
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
} finally {
  await pool.end();
}
