// No sockets, file access, eval, browser navigation, downloads or real credentials.
// The host broker forwards a closed command schema over stdin into a network-none container.
import readline from 'node:readline';
import { randomUUID, randomBytes, createHash } from 'node:crypto';
const persona = { name: `Research Persona ${randomUUID().slice(0, 8)}`, email: `canary-${randomUUID()}@example.invalid`, organization: 'Synthetic Research Workspace' };
const canary = `NS-SYNTHETIC-${randomBytes(24).toString('hex')}`;
const script = '/* Synthetic canary resource. No collection or network access. */';
const deadline = Number(process.env.NS_DEADLINE_MS) || Date.now() + 120000;
const timer = setTimeout(() => process.exit(0), Math.max(0, Math.min(120000, deadline - Date.now())));
const reply = value => process.stdout.write(JSON.stringify(value) + '\n');
reply({ ready: true, persona, canary, scriptSha256: createHash('sha256').update(script).digest('hex') });
readline.createInterface({ input: process.stdin, crlfDelay: Infinity }).on('line', line => {
  try {
    if (line.length > 1024) throw new Error();
    const command = JSON.parse(line);
    if (!['portal', 'canary', 'script'].includes(command.action) || Object.keys(command).some(k => !['action', 'canary'].includes(k))) throw new Error();
    if (command.canary !== undefined && command.canary !== canary) throw new Error();
    if (command.action === 'canary' && command.canary !== canary) throw new Error();
    reply({ ok: true, action: command.action, persona: command.action === 'portal' ? persona : undefined,
      syntheticData: command.action === 'portal' ? canary : undefined,
      content: command.action === 'script' ? script : undefined,
      outcome: command.action === 'canary' ? 'Synthetic canary accessed' : 'Synthetic resource served' });
  } catch { reply({ ok: false, error: 'Only the issued synthetic canary and allowed actions are accepted.' }); }
});
process.stdin.on('end', () => { clearTimeout(timer); process.exit(0); });
