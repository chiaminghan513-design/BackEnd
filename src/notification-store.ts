import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { randomUUID } from 'node:crypto';

type Message = { id: string; phone: string | null; title: string; body: string; createdAt: string; sender: string; readers: string[] };
const phoneKey = (phone: string) => phone.replace(/\D/g, '');
export class NotificationStore {
  private pending: Promise<unknown> = Promise.resolve();
  constructor(private readonly path: string) {}
  private async load(): Promise<Message[]> {
    try {
      const value = JSON.parse(await readFile(this.path, 'utf8'));
      if (!Array.isArray(value)) throw new Error('Invalid notification store.');
      return value;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw error;
    }
  }
  private change<T>(action: (rows: Message[]) => T): Promise<T> {
    const result = this.pending.then(async () => {
      const rows = await this.load();
      const value = action(rows);
      await mkdir(dirname(this.path), { recursive: true });
      const temporary = `${this.path}.${randomUUID()}.tmp`;
      await writeFile(temporary, JSON.stringify(rows), { mode: 0o600 });
      await rename(temporary, this.path);
      return value;
    });
    this.pending = result.catch(() => undefined);
    return result;
  }
  async send(phone: string | null, title: string, body: string, sender: string) {
    if (phone !== null && !/^\+?\d{8,15}$/.test(phone)) throw Object.assign(new Error('Enter a valid recipient phone number.'), { status: 400 });
    if (!title.trim() || !body.trim() || title.length > 160 || body.length > 4000) throw Object.assign(new Error('Enter a title (up to 160 characters) and message (up to 4,000 characters).'), { status: 400 });
    return this.change(rows => {
      const message: Message = { id: `local-notification-${randomUUID()}`, phone: phone === null ? null : phoneKey(phone), title: title.trim(), body: body.trim(), createdAt: new Date().toISOString(), sender, readers: [] };
      rows.push(message);
      return { success: true, NotificationId: message.id, message: 'Message saved to the member inbox.', delivery: 'in-app' };
    });
  }
  private visible(row: Message, phone: string) { return row.phone === null || row.phone === phoneKey(phone); }
  private card(row: Message, phone: string) {
    return { NotificationId: row.id, Title: row.title, Message: row.body, Content: row.body, Description: row.body, PushTime: row.createdAt, NotificationType: 'Eduvo', IsUnread: !row.readers.includes(phoneKey(phone)), Source: 'EduvoBackend' };
  }
  async list(phone: string) {
    await this.pending;
    return (await this.load()).filter(row => this.visible(row, phone)).map(row => this.card(row, phone));
  }
  async detail(phone: string, id: string) {
    await this.pending;
    const row = (await this.load()).find(row => row.id === id && this.visible(row, phone));
    if (!row) throw Object.assign(new Error('Notification not found.'), { status: 404 });
    return this.card(row, phone);
  }
  async read(phone: string, id?: string) {
    return this.change(rows => {
      const selected = rows.filter(row => this.visible(row, phone) && (!id || row.id === id));
      if (id && !selected.length) throw Object.assign(new Error('Notification not found.'), { status: 404 });
      for (const row of selected) if (!row.readers.includes(phoneKey(phone))) row.readers.push(phoneKey(phone));
      return { success: true };
    });
  }
}
