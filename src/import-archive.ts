import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import { dirname } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';

export const importKinds = new Set(['members', 'banners', 'rewards', 'merchants', 'outlets', 'wallets', 'topups', 'spends', 'redemptions', 'points', 'stampassigns', 'stamptransactions', 'stamps']);
type ArchivedRow = { id: string; kind: string; archivedAt: string; data: Record<string, unknown> };
export class ImportArchive {
  private pending: Promise<unknown> = Promise.resolve();
  constructor(private readonly path: string) {}
  private async load(): Promise<ArchivedRow[]> {
    try {
      const rows = JSON.parse(await readFile(this.path, 'utf8'));
      if (!Array.isArray(rows)) throw new Error('Invalid import archive.');
      return rows;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    }
  }
  async list(kind?: string) {
    if (kind && !importKinds.has(kind)) throw Object.assign(new Error('Unknown import format.'), { status: 400 });
    await this.pending;
    return (await this.load()).filter(row => !kind || row.kind === kind);
  }
  save(kind: string, input: unknown) {
    if (!importKinds.has(kind) || !input || typeof input !== 'object' || Array.isArray(input)) throw Object.assign(new Error('Choose a valid import format and object row.'), { status: 400 });
    // The archive is not an authentication database: never retain credentials.
    const data = Object.fromEntries(Object.entries(input as Record<string, unknown>)
      .filter(([key]) => !/password|secret|token/i.test(key)).sort(([left], [right]) => left.localeCompare(right)));
    const id = createHash('sha256').update(kind + JSON.stringify(data)).digest('hex');
    const result = this.pending.then(async () => {
      const rows = await this.load();
      if (rows.some(row => row.id === id)) return { success: true, archived: true, duplicate: true, id, message: 'Already archived locally; live API data is unchanged.' };
      rows.push({ id, kind, archivedAt: new Date().toISOString(), data });
      await mkdir(dirname(this.path), { recursive: true });
      const temporary = `${this.path}.${randomUUID()}.tmp`;
      await writeFile(temporary, JSON.stringify(rows), { mode: 0o600 });
      await rename(temporary, this.path);
      return { success: true, archived: true, duplicate: false, id, message: 'Saved to the local archive; live API data is unchanged.' };
    });
    this.pending = result.catch(() => undefined);
    return result;
  }
}
