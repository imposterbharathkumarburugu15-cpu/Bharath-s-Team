import { spawn, execFile, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { promisify } from 'node:util';
import { createInterface } from 'node:readline';
const exec = promisify(execFile);
export interface SandboxHandle { ready: Promise<any>; command(value: { action: string; canary?: string }): Promise<any>; stop(): Promise<void>; }
export interface SandboxRunner { available(): Promise<boolean>; start(id: string, seconds: number): SandboxHandle; }

export class DockerRunner implements SandboxRunner {
  async available() {
    try { await exec('docker', ['image', 'inspect', '--format', '{{.Id}}', 'neuroshield-honeytrap:local'], { timeout: 3000, maxBuffer: 4096 }); return true; }
    catch { return false; }
  }
  start(id: string, seconds: number): SandboxHandle {
    if (!/^NS-TRAP-[a-f0-9-]+$/.test(id) || !Number.isInteger(seconds) || seconds < 10 || seconds > 120) throw new Error('Invalid sandbox limits');
    const name = `ns-${id.toLowerCase()}`;
    const child = spawn('docker', ['run', '--rm', '--pull=never', '--name', name, '--label', 'neuroshield.honeytrap=true',
      '--env', `NS_DEADLINE_MS=${Date.now() + seconds * 1000}`, '--network', 'none', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
      '--user', '10001:10001', '--pids-limit', '32', '--memory', '64m', '--cpus', '0.25', '--init', '-i', 'neuroshield-honeytrap:local'], { stdio: 'pipe' }) as ChildProcessWithoutNullStreams;
    let readyResolve: (v: any) => void, readyReject: (e: Error) => void;
    const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
    let pending: { resolve(v: any): void; reject(e: Error): void; timer: NodeJS.Timeout } | undefined;
    let closed = false;
    const startup = setTimeout(() => { readyReject(new Error('Sandbox startup timed out')); void stop(); }, 5000);
    const fail = () => {
      closed = true; clearTimeout(startup);
      readyReject(new Error('Isolated container unavailable'));
      if (pending) { clearTimeout(pending.timer); pending.reject(new Error('Sandbox stopped')); pending = undefined; }
    };
    child.on('error', fail); child.on('exit', fail); child.stderr.resume();
    createInterface({ input: child.stdout }).on('line', line => {
      if (line.length > 8192) { void stop(); return; }
      try {
        const event = JSON.parse(line);
        if (event.ready) { clearTimeout(startup); readyResolve(event); }
        else if (pending) { clearTimeout(pending.timer); pending.resolve(event); pending = undefined; }
      } catch { void stop(); }
    });
    const deadline = setTimeout(() => void stop(), seconds * 1000);
    async function stop() {
      clearTimeout(deadline); clearTimeout(startup); fail();
      child.stdin.end(); child.kill('SIGKILL');
      // Killing a docker CLI alone does not necessarily stop its container.
      await exec('docker', ['rm', '-f', name], { timeout: 4000, maxBuffer: 4096 }).catch(() => {});
    }
    return {
      ready,
      async command(value) {
        await ready;
        if (closed) throw new Error('Sandbox is stopped');
        if (pending) throw new Error('Sandbox busy; retry the controlled action');
        return new Promise((resolve, reject) => {
          pending = { resolve, reject, timer: setTimeout(() => { void stop(); }, 2000) };
          child.stdin.write(JSON.stringify(value) + '\n');
        });
      }, stop,
    };
  }
}
