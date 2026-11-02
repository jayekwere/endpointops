import { lookup } from 'node:dns/promises';
import { createConnection } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { isIP } from 'node:net';
import { performance } from 'node:perf_hooks';
import { z } from 'zod';
export interface NetworkDiagnostics {
  dns: 'pass' | 'fail';
  tcp: 'pass' | 'fail' | 'unknown';
  tls: 'pass' | 'fail' | 'unknown';
  durationMs: number;
}
/** The target is operator CLI configuration, never an API request field. No application credentials are sent. */
export async function diagnoseNetwork(
  host: string,
  port = 443,
  timeout = 1500,
): Promise<NetworkDiagnostics> {
  z.string()
    .regex(/^[a-zA-Z0-9.-]{1,253}$/)
    .parse(host);
  z.number().int().min(1).max(65535).parse(port);
  const started = performance.now();
  const result: NetworkDiagnostics = { dns: 'fail', tcp: 'unknown', tls: 'unknown', durationMs: 0 };
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const addresses = await Promise.race([
      lookup(host, { all: true }),
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error('DNS timeout')), timeout);
      }),
    ]);
    if (timer) clearTimeout(timer);
    const address = addresses.find((a) => a.family === 4) ?? addresses[0];
    if (!address) throw new Error('No DNS answer');
    result.dns = 'pass';
    result.tcp = await new Promise<'pass' | 'fail'>((resolve) => {
      const socket = createConnection({ host: address.address, port });
      socket.setTimeout(timeout);
      const finish = (state: 'pass' | 'fail') => {
        socket.destroy();
        resolve(state);
      };
      socket.once('connect', () => finish('pass'));
      socket.once('error', () => finish('fail'));
      socket.once('timeout', () => finish('fail'));
    });
    if (result.tcp === 'pass')
      result.tls = await new Promise<'pass' | 'fail'>((resolve) => {
        const socket = tlsConnect({
          host: address.address,
          port,
          ...(isIP(host) ? {} : { servername: host }),
          rejectUnauthorized: true,
        });
        socket.setTimeout(timeout);
        const finish = (state: 'pass' | 'fail') => {
          socket.destroy();
          resolve(state);
        };
        socket.once('secureConnect', () => finish(socket.authorized ? 'pass' : 'fail'));
        socket.once('error', () => finish('fail'));
        socket.once('timeout', () => finish('fail'));
      });
  } catch {
  } finally {
    if (timer) clearTimeout(timer);
  }
  result.durationMs = Math.round((performance.now() - started) * 100) / 100;
  return result;
}
