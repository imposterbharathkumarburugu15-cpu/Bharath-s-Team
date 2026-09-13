import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import path from 'node:path';

/** Durable, single-deployment SOC store. Raw messages and credentials never enter it. */
export class IntelligenceStore {
  readonly db: DatabaseSync;
  constructor(filename = process.env.NEUROSHIELD_INTEL_DB || 'data/intelligence.sqlite') {
    if (filename !== ':memory:') mkdirSync(path.dirname(path.resolve(filename)), { recursive: true, mode: 0o700 });
    this.db = new DatabaseSync(filename);
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;
      CREATE TABLE IF NOT EXISTS records (kind TEXT NOT NULL, id TEXT NOT NULL, json TEXT NOT NULL, PRIMARY KEY(kind,id));`);
  }
  get<T>(kind: string, id: string): T | undefined {
    const row = this.db.prepare('SELECT json FROM records WHERE kind=? AND id=?').get(kind, id) as { json: string } | undefined;
    return row ? JSON.parse(row.json) : undefined;
  }
  list<T>(kind: string, limit = 5000): T[] {
    return this.db.prepare('SELECT json FROM records WHERE kind=? ORDER BY rowid DESC LIMIT ?').all(kind, Math.max(1, Math.min(5000, limit))).map((r: any) => JSON.parse(r.json));
  }
  put(kind: string, record: { id: string; [key: string]: any }) {
    this.db.prepare('INSERT INTO records(kind,id,json) VALUES(?,?,?) ON CONFLICT(kind,id) DO UPDATE SET json=excluded.json').run(kind, record.id, JSON.stringify(record));
  }
  transaction<T>(work: () => T): T {
    this.db.exec('BEGIN IMMEDIATE');
    try { const result = work(); this.db.exec('COMMIT'); return result; }
    catch (e) { this.db.exec('ROLLBACK'); throw e; }
  }
  close() { this.db.close(); }
}
