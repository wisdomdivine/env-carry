import http from 'node:http';
import os from 'node:os';
import { EncryptedEnvelope } from '../crypto.js';

export interface RelayServerOptions {
  port?: number;
  timeoutMs?: number;
}

/**
 * Retrieves the local network IPv4 address for peer-to-peer Wi-Fi / LAN transfer.
 */
export function getLocalIp(): string {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name] || []) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return '127.0.0.1';
}

/**
 * Starts a single-use, ephemeral HTTP transfer server for the encrypted payload.
 * Once fetched or timed out, the server shuts down immediately (Burn-After-Reading).
 */
export function startEphemeralRelay(
  envelope: EncryptedEnvelope,
  options: RelayServerOptions = {}
): Promise<{
  url: string;
  close: () => void;
  done: Promise<{ success: boolean; remoteIp?: string }>;
}> {
  return new Promise((resolveReady) => {
    let resolveDone: (val: { success: boolean; remoteIp?: string }) => void;
    const done = new Promise<{ success: boolean; remoteIp?: string }>((res) => {
      resolveDone = res;
    });

    const payloadJson = JSON.stringify(envelope);

    const server = http.createServer((req, res) => {
      // Set CORS headers so it can be fetched via curl, browser, or CLI
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', '*');

      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      if (req.method === 'GET' && req.url === '/carry') {
        const clientIp = req.socket.remoteAddress || 'unknown';
        res.writeHead(200, {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payloadJson),
          'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0'
        });
        res.end(payloadJson, () => {
          // Burn after reading: close server immediately after successful transfer
          setTimeout(() => {
            server.close();
            resolveDone({ success: true, remoteIp: clientIp });
          }, 100);
        });
      } else {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
      }
    });

    const timeout = options.timeoutMs || 10 * 60 * 1000; // 10 minutes default
    const timer = setTimeout(() => {
      server.close();
      resolveDone({ success: false });
    }, timeout);

    server.listen(options.port || 0, '0.0.0.0', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      const ip = getLocalIp();
      const url = `http://${ip}:${port}/carry`;

      resolveReady({
        url,
        close: () => {
          clearTimeout(timer);
          server.close();
          resolveDone({ success: false });
        },
        done
      });
    });
  });
}

/**
 * Fetches an encrypted envelope from an ephemeral relay URL.
 */
export async function fetchRelayEnvelope(url: string): Promise<EncryptedEnvelope> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`Failed to fetch carry payload from relay: HTTP ${res.status}`);
  }
  return (await res.json()) as EncryptedEnvelope;
}
