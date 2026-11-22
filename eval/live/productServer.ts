/**
 * Starts a throwaway DefySwarm product server for verification and live
 * validation. The server runs in production mode from a temporary working
 * directory so it can never read or write the repository's live data/ folder.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { REPO_ROOT } from '../config.ts';

export interface ProductServer {
  baseUrl: string;
  port: number;
  dir: string;
  process: ChildProcess;
  stop: () => Promise<void>;
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.unref();
    server.on('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      server.close(() => resolve(port));
    });
  });
}

async function waitForBootstrap(baseUrl: string, timeoutMs = 20_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  let lastError = '';
  while (Date.now() < deadline) {
    try {
      const response = await fetch(`${baseUrl}/api/bootstrap`, {
        signal: AbortSignal.timeout(1500),
      });
      if (response.ok) return;
      lastError = `HTTP ${response.status}`;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 200));
  }
  throw new Error(`Product server did not become ready: ${lastError}`);
}

export async function startProductServer(options: {
  distDir?: string;
  port?: number;
  extraEnv?: Record<string, string>;
} = {}): Promise<ProductServer> {
  const distDir = options.distDir ?? path.join(REPO_ROOT, 'dist');
  if (!fs.existsSync(path.join(distDir, 'index.html'))) {
    throw new Error(
      `No production build at ${distDir}. Run "npm run build" before live validation or verification.`,
    );
  }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'defyswarm-eval-'));
  fs.cpSync(distDir, path.join(dir, 'dist'), { recursive: true });
  fs.mkdirSync(path.join(dir, 'data'), { recursive: true });

  const port = options.port ?? (await freePort());
  const tsxBin = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsx');
  const serverEntry = path.join(REPO_ROOT, 'server.ts');
  const child = spawn(tsxBin, [serverEntry], {
    cwd: dir,
    env: {
      ...process.env,
      NODE_ENV: 'production',
      PORT: String(port),
      EVAL_LAB: '',
      VITE_EVAL_LAB: '',
      DEMO_LOCK: '',
      ...(options.extraEnv ?? {}),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let output = '';
  child.stdout?.on('data', (chunk) => {
    output += String(chunk);
  });
  child.stderr?.on('data', (chunk) => {
    output += String(chunk);
  });

  const baseUrl = `http://127.0.0.1:${port}`;
  try {
    await waitForBootstrap(baseUrl);
  } catch (error) {
    child.kill('SIGKILL');
    fs.rmSync(dir, { recursive: true, force: true });
    throw new Error(
      `${error instanceof Error ? error.message : error}\nServer output:\n${output.slice(-2000)}`,
    );
  }

  const stop = async (): Promise<void> => {
    if (!child.killed) {
      child.kill('SIGTERM');
      await new Promise<void>((resolve) => {
        const timer = setTimeout(() => {
          child.kill('SIGKILL');
          resolve();
        }, 3000);
        child.once('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });
    }
    fs.rmSync(dir, { recursive: true, force: true });
  };

  return { baseUrl, port, dir, process: child, stop };
}

export async function api<T>(
  baseUrl: string,
  route: string,
  init: RequestInit = {},
): Promise<T> {
  const response = await fetch(`${baseUrl}${route}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      'x-defyswarm-role': 'admin',
      ...(init.headers ?? {}),
    },
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${route} returned HTTP ${response.status}: ${text.slice(0, 400)}`);
  }
  return (text ? JSON.parse(text) : {}) as T;
}
