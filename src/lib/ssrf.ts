import dns from 'node:dns/promises';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';

export interface SafeFetchResponse {
  statusCode: number;
  statusMessage: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  url: string;
  ip: string;
  durationMs: number;
}

/**
 * Checks whether an IPv4 or IPv6 address belongs to private, loopback, link-local,
 * cloud metadata, or reserved ranges to prevent SSRF vulnerabilities.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  if (!net.isIP(ip)) {
    return true; // Not a valid IP
  }

  // IPv4 Checks
  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(isNaN)) return true;

    // 0.0.0.0/8 (Current network)
    if (parts[0] === 0) return true;

    // 127.0.0.0/8 (Loopback)
    if (parts[0] === 127) return true;

    // 10.0.0.0/8 (Private)
    if (parts[0] === 10) return true;

    // 172.16.0.0/12 (Private)
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;

    // 192.168.0.0/16 (Private)
    if (parts[0] === 192 && parts[1] === 168) return true;

    // 169.254.0.0/16 (Link-local / Cloud metadata: 169.254.169.254)
    if (parts[0] === 169 && parts[1] === 254) return true;

    // 100.64.0.0/10 (Carrier-grade NAT)
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true;

    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (Test-Net documentation)
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return true;
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return true;
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return true;

    // 224.0.0.0/4 (Multicast)
    if (parts[0] >= 224 && parts[0] <= 239) return true;

    // 240.0.0.0/4 (Reserved / Future use)
    if (parts[0] >= 240) return true;

    // 255.255.255.255 (Broadcast)
    if (ip === '255.255.255.255') return true;

    return false;
  }

  // IPv6 Checks
  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    // Loopback ::1
    if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;
    // Unspecified ::
    if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') return true;
    // IPv6 link-local (fe80::/10)
    if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || normalized.startsWith('fea') || normalized.startsWith('feb')) return true;
    // Unique Local Address (fc00::/7)
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
    // IPv4-mapped IPv6 (::ffff:127.0.0.1, etc.)
    if (normalized.includes('::ffff:')) {
      const ipv4Part = normalized.split('::ffff:')[1];
      if (ipv4Part && net.isIPv4(ipv4Part)) {
        return isPrivateOrReservedIp(ipv4Part);
      }
    }
  }

  return false;
}

/**
 * Validates a target URL against SSRF rules:
 * - Must be http or https
 * - Port must only be 80 or 443
 * - Hostname must resolve to a non-private public IP address
 */
export async function validateTargetUrl(
  rawUrl: string,
  options: { allowInternalTestTarget?: boolean } = {}
): Promise<{ valid: boolean; error?: string; url?: URL; ip?: string }> {
  try {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl.startsWith('http://') || rawUrl.startsWith('https://') ? rawUrl : `https://${rawUrl}`);
    } catch {
      return { valid: false, error: 'Malformed URL provided.' };
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { valid: false, error: 'Only HTTP and HTTPS protocols are permitted.' };
    }

    const allowInternal = Boolean(options.allowInternalTestTarget);
    const port = parsed.port ? parseInt(parsed.port, 10) : (parsed.protocol === 'https:' ? 443 : 80);
    if (!allowInternal && port !== 80 && port !== 443) {
      return { valid: false, error: 'Only standard web ports (80, 443) are allowed for scanning.' };
    }

    const hostname = parsed.hostname;
    if (!hostname || (!allowInternal && (hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.internal')))) {
      return { valid: false, error: 'Target host is not permitted.' };
    }

    if (allowInternal && (hostname === '127.0.0.1' || hostname === 'localhost')) {
      return { valid: true, url: parsed, ip: '127.0.0.1' };
    }

    // Resolve DNS
    const addresses = await dns.lookup(hostname, { all: true });
    if (!addresses || addresses.length === 0) {
      return { valid: false, error: `Could not resolve hostname "${hostname}".` };
    }

    // Check every resolved address
    if (!allowInternal) {
      for (const record of addresses) {
        if (isPrivateOrReservedIp(record.address)) {
          return { valid: false, error: `Access to private/reserved IP address (${record.address}) is blocked for security.` };
        }
      }
    }

    return {
      valid: true,
      url: parsed,
      ip: addresses[0].address
    };
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { valid: false, error: `DNS resolution failed: ${msg}` };
  }
}

/**
 * Safe HTTP Request wrapper with:
 * - Pre-flight IP validation & SSRF prevention on target and every redirect
 * - Maximum 3 redirects followed safely
 * - 8000ms timeout
 * - 2MB max response stream limit
 * - Safe user agent identifying WP Sentinel security scanner
 */
export async function safeFetch(
  targetUrl: string,
  options: {
    method?: 'GET' | 'HEAD' | 'POST';
    headers?: Record<string, string>;
    body?: string;
    maxRedirects?: number;
    timeoutMs?: number;
    maxBytes?: number;
    allowInternalTestTarget?: boolean;
  } = {}
): Promise<SafeFetchResponse> {
  const method = options.method || 'GET';
  const maxRedirects = options.maxRedirects ?? 3;
  const timeoutMs = options.timeoutMs ?? 8000;
  const maxBytes = options.maxBytes ?? 2 * 1024 * 1024; // 2MB max response size

  let currentUrl = targetUrl;
  let redirectsCount = 0;
  const startTime = Date.now();

  while (redirectsCount <= maxRedirects) {
    const validation = await validateTargetUrl(currentUrl, {
      allowInternalTestTarget: options.allowInternalTestTarget
    });
    if (!validation.valid || !validation.url || !validation.ip) {
      throw new Error(`SSRF Block: ${validation.error}`);
    }

    const parsedUrl = validation.url;
    const ip = validation.ip;
    const isHttps = parsedUrl.protocol === 'https:';
    const requester = isHttps ? https : http;

    const requestHeaders: Record<string, string> = {
      'User-Agent': 'Mozilla/5.0 (compatible; WPSentinel/1.0; +https://wpsentinel.security/bot; passive security auditor)',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Connection': 'close',
      ...(options.headers || {})
    };

    const result = await new Promise<SafeFetchResponse>((resolve, reject) => {
      const timer = setTimeout(() => {
        req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      const req = requester.request(
        parsedUrl,
        {
          method,
          headers: requestHeaders,
          timeout: timeoutMs,
          // DNS Rebinding Guard: Force socket connection to the exact pre-validated IP
          lookup: (_hostname, lookupOptions, cb) => {
            const family = net.isIPv6(ip) ? 6 : 4;
            if (typeof lookupOptions === 'function') {
              (lookupOptions as unknown as (err: NodeJS.ErrnoException | null, address: string, family: number) => void)(null, ip, family);
              return;
            }
            if (lookupOptions && (lookupOptions as { all?: boolean }).all) {
              (cb as unknown as (err: NodeJS.ErrnoException | null, addresses: Array<{ address: string; family: number }>) => void)(null, [{ address: ip, family }]);
              return;
            }
            cb(null, ip, family);
          },
          servername: parsedUrl.hostname,
          // Permissive for initial handshake check, but we audit SSL separately!
          rejectUnauthorized: false
        },
        (res) => {
          let receivedBytes = 0;
          const chunks: Buffer[] = [];

          res.on('data', (chunk: Buffer) => {
            receivedBytes += chunk.length;
            if (receivedBytes > maxBytes) {
              res.destroy();
              resolve({
                statusCode: res.statusCode || 200,
                statusMessage: res.statusMessage || '',
                headers: res.headers,
                body: Buffer.concat(chunks).toString('utf-8', 0, maxBytes),
                url: currentUrl,
                ip,
                durationMs: Date.now() - startTime
              });
              return;
            }
            chunks.push(chunk);
          });

          res.on('end', () => {
            clearTimeout(timer);
            const body = Buffer.concat(chunks).toString('utf-8');
            resolve({
              statusCode: res.statusCode || 200,
              statusMessage: res.statusMessage || '',
              headers: res.headers,
              body,
              url: currentUrl,
              ip,
              durationMs: Date.now() - startTime
            });
          });

          res.on('error', (err) => {
            clearTimeout(timer);
            reject(err);
          });
        }
      );

      req.on('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });

      if (options.body && method === 'POST') {
        req.write(options.body);
      }

      req.end();
    });

    // Check for redirect (301, 302, 307, 308)
    if ([301, 302, 303, 307, 308].includes(result.statusCode) && result.headers.location) {
      redirectsCount++;
      if (redirectsCount > maxRedirects) {
        return result; // Stop redirect loop
      }

      const redirectLocation = Array.isArray(result.headers.location)
        ? result.headers.location[0]
        : result.headers.location;

      try {
        const nextUrl = new URL(redirectLocation, currentUrl).toString();
        currentUrl = nextUrl;
        continue;
      } catch {
        return result;
      }
    }

    return result;
  }

  throw new Error('Too many redirects encountered.');
}
