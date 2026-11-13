import dns from 'node:dns/promises';
import net from 'node:net';
import http from 'node:http';
import https from 'node:https';
import tls from 'node:tls';
import { URL } from 'node:url';
import { V2TlsCertificate } from '../types/v2.ts';

export interface SafeFetchV2Response {
  statusCode: number;
  statusMessage: string;
  headers: Record<string, string | string[] | undefined>;
  body: string;
  url: string;
  ip: string;
  durationMs: number;
}

export function isPrivateOrReservedIp(ip: string): boolean {
  if (!net.isIP(ip)) return true;

  if (net.isIPv4(ip)) {
    const parts = ip.split('.').map(Number);
    if (parts.length !== 4 || parts.some(isNaN)) return true;
    if (parts[0] === 0) return true; // 0.0.0.0/8
    if (parts[0] === 127) return true; // 127.0.0.0/8 loopback
    if (parts[0] === 10) return true; // 10.0.0.0/8 private
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true; // 172.16.0.0/12
    if (parts[0] === 192 && parts[1] === 168) return true; // 192.168.0.0/16
    if (parts[0] === 169 && parts[1] === 254) return true; // 169.254.0.0/16 cloud metadata
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return true; // CGNAT
    if (parts[0] === 192 && parts[1] === 0 && parts[2] === 2) return true; // TEST-NET-1
    if (parts[0] === 198 && parts[1] === 51 && parts[2] === 100) return true; // TEST-NET-2
    if (parts[0] === 203 && parts[1] === 0 && parts[2] === 113) return true; // TEST-NET-3
    if (parts[0] >= 224) return true; // Multicast & reserved
    return false;
  }

  if (net.isIPv6(ip)) {
    const normalized = ip.toLowerCase();
    if (normalized === '::1' || normalized === '0:0:0:0:0:0:0:1') return true;
    if (normalized === '::' || normalized === '0:0:0:0:0:0:0:0') return true;
    if (
      normalized.startsWith('fe8') ||
      normalized.startsWith('fe9') ||
      normalized.startsWith('fea') ||
      normalized.startsWith('feb')
    ) {
      return true;
    }
    if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;
    if (normalized.includes('::ffff:')) {
      const ipv4Part = normalized.split('::ffff:')[1];
      if (ipv4Part && net.isIPv4(ipv4Part)) {
        return isPrivateOrReservedIp(ipv4Part);
      }
    }
  }

  return false;
}

export async function validateV2TargetUrl(
  rawUrl: string,
  options: { allowInternalTestTarget?: boolean } = {}
): Promise<{ valid: boolean; error?: string; url?: URL; ip?: string }> {
  try {
    let parsed: URL;
    try {
      const trimmed = rawUrl.trim();
      parsed = new URL(
        trimmed.startsWith('http://') || trimmed.startsWith('https://') ? trimmed : `https://${trimmed}`
      );
    } catch {
      return { valid: false, error: 'Malformed URL provided.' };
    }

    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return { valid: false, error: 'Only HTTP and HTTPS protocols are permitted.' };
    }

    if (parsed.username || parsed.password) {
      return { valid: false, error: 'Embedded URL credentials are not permitted.' };
    }

    const port = parsed.port ? parseInt(parsed.port, 10) : parsed.protocol === 'https:' ? 443 : 80;
    if (!options.allowInternalTestTarget && port !== 80 && port !== 443) {
      return { valid: false, error: 'Only standard web ports (80, 443) are allowed for scanning.' };
    }

    const hostname = parsed.hostname.toLowerCase();
    if (
      !options.allowInternalTestTarget &&
      (!hostname || hostname === 'localhost' || hostname.endsWith('.local') || hostname.endsWith('.internal'))
    ) {
      return { valid: false, error: 'Target host is not permitted.' };
    }

    if (net.isIP(hostname)) {
      if (!options.allowInternalTestTarget && isPrivateOrReservedIp(hostname)) {
        return {
          valid: false,
          error: `Access to private/reserved IP address (${hostname}) is blocked for security.`
        };
      }
      return { valid: true, url: parsed, ip: hostname };
    }

    const addresses = await dns.lookup(hostname, { all: true });
    if (!addresses || addresses.length === 0) {
      return { valid: false, error: `Could not resolve hostname "${hostname}".` };
    }

    if (!options.allowInternalTestTarget) {
      for (const record of addresses) {
        if (isPrivateOrReservedIp(record.address)) {
          return {
            valid: false,
            error: `Access to private/reserved IP address (${record.address}) is blocked for security.`
          };
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

export function isUrlInScope(
  candidateUrl: string,
  rootUrl: URL,
  scope: 'same-origin' | 'include-subdomains'
): boolean {
  try {
    const parsed = new URL(candidateUrl);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return false;

    const rootHost = rootUrl.hostname.toLowerCase();
    const candHost = parsed.hostname.toLowerCase();

    if (scope === 'same-origin') {
      const rootPort = rootUrl.port || (rootUrl.protocol === 'https:' ? '443' : '80');
      const candPort = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
      return candHost === rootHost && candPort === rootPort;
    }

    return candHost === rootHost || candHost.endsWith(`.${rootHost}`);
  } catch {
    return false;
  }
}

export async function safeFetchV2(
  targetUrl: string,
  options: {
    method?: 'GET' | 'HEAD';
    headers?: Record<string, string>;
    maxRedirects?: number;
    timeoutMs?: number;
    maxBytes?: number;
    allowInternalTestTarget?: boolean;
    enforceScopeRoot?: URL;
    scopeMode?: 'same-origin' | 'include-subdomains';
  } = {}
): Promise<SafeFetchV2Response> {
  const method = options.method || 'GET';
  const maxRedirects = options.maxRedirects ?? 3;
  const timeoutMs = options.timeoutMs ?? 8000;
  const maxBytes = options.maxBytes ?? 2 * 1024 * 1024;

  let currentUrl = targetUrl;
  let redirectsCount = 0;
  const startTime = Date.now();

  while (redirectsCount <= maxRedirects) {
    const validation = await validateV2TargetUrl(currentUrl, {
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
      'User-Agent': 'Mozilla/5.0 (compatible; SiteSentinelV2/2.0; passive security auditor)',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Language': 'en-US,en;q=0.5',
      'Connection': 'close',
      ...(options.headers || {})
    };

    const result = await new Promise<SafeFetchV2Response>((resolve, reject) => {
      const timer = setTimeout(() => {
        req.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      const req = requester.request(
        parsedUrl,
        {
          method,
          headers: requestHeaders,
          timeout: timeoutMs,
          lookup: (_hostname, lookupOptions, cb) => {
            const family = net.isIPv6(ip) ? 6 : 4;
            if (typeof lookupOptions === 'function') {
              (lookupOptions as unknown as (err: NodeJS.ErrnoException | null, address: string, family: number) => void)(
                null,
                ip,
                family
              );
              return;
            }
            if (lookupOptions && (lookupOptions as { all?: boolean }).all) {
              (cb as unknown as (err: NodeJS.ErrnoException | null, addresses: Array<{ address: string; family: number }>) => void)(
                null,
                [{ address: ip, family }]
              );
              return;
            }
            cb(null, ip, family);
          },
          servername: parsedUrl.hostname,
          rejectUnauthorized: false
        },
        (res) => {
          let receivedBytes = 0;
          const chunks: Buffer[] = [];

          res.on('data', (chunk: Buffer) => {
            receivedBytes += chunk.length;
            if (receivedBytes > maxBytes) {
              res.destroy();
              clearTimeout(timer);
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
            resolve({
              statusCode: res.statusCode || 200,
              statusMessage: res.statusMessage || '',
              headers: res.headers,
              body: Buffer.concat(chunks).toString('utf-8'),
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

      req.end();
    });

    if ([301, 302, 303, 307, 308].includes(result.statusCode) && result.headers.location) {
      redirectsCount++;
      if (redirectsCount > maxRedirects) {
        return result;
      }

      const redirectLocation = Array.isArray(result.headers.location)
        ? result.headers.location[0]
        : result.headers.location;

      try {
        const nextUrl = new URL(redirectLocation, currentUrl).toString();
        if (options.enforceScopeRoot && options.scopeMode) {
          if (!isUrlInScope(nextUrl, options.enforceScopeRoot, options.scopeMode)) {
            return result; // Do not follow redirects outside authorized scope
          }
        }
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

export async function inspectTlsCertificate(
  hostname: string,
  ip: string,
  port: number = 443
): Promise<V2TlsCertificate> {
  return new Promise((resolve) => {
    let settled = false;
    const finish = (cert: V2TlsCertificate) => {
      if (settled) return;
      settled = true;
      resolve(cert);
    };

    const socket = tls.connect(
      {
        host: ip,
        port,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 6000
      },
      () => {
        try {
          const peer = socket.getPeerCertificate();
          const protocol = socket.getProtocol() || undefined;
          const cipher = socket.getCipher()?.name || undefined;
          const authorized = socket.authorized;
          const authError = socket.authorizationError ? String(socket.authorizationError) : undefined;

          if (!peer || Object.keys(peer).length === 0) {
            socket.end();
            finish({
              valid: false,
              protocol,
              cipher,
              error: 'No TLS certificate presented by peer.'
            });
            return;
          }

          const validToDate = peer.valid_to ? new Date(peer.valid_to) : null;
          const daysRemaining = validToDate
            ? Math.floor((validToDate.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
            : undefined;

          const pickCertField = (val: string | string[] | undefined): string | undefined =>
            Array.isArray(val) ? val[0] : val;

          const issuerStr = peer.issuer
            ? pickCertField(peer.issuer.O) || pickCertField(peer.issuer.CN) || JSON.stringify(peer.issuer)
            : undefined;
          const subjectStr = peer.subject
            ? pickCertField(peer.subject.CN) || pickCertField(peer.subject.O) || JSON.stringify(peer.subject)
            : undefined;

          const selfSigned =
            Boolean(authError && authError.includes('SELF_SIGNED')) ||
            (Boolean(issuerStr && subjectStr) && issuerStr === subjectStr && !authorized);

          socket.end();
          finish({
            valid: authorized && (daysRemaining === undefined || daysRemaining >= 0),
            protocol,
            cipher,
            issuer: issuerStr,
            subject: subjectStr,
            validFrom: peer.valid_from,
            validTo: peer.valid_to,
            daysRemaining,
            selfSigned,
            error: authorized ? undefined : authError
          });
        } catch (err: unknown) {
          socket.destroy();
          finish({
            valid: false,
            error: err instanceof Error ? err.message : 'TLS inspection error'
          });
        }
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      finish({ valid: false, error: 'TLS handshake timed out.' });
    });

    socket.on('error', (err) => {
      socket.destroy();
      finish({ valid: false, error: err.message });
    });
  });
}
