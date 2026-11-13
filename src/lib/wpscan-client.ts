import { queryCatalog, KnownVulnerability } from './vulnerability-db.ts';
import { FindingSeverity, WpScanIntelligenceSource } from '../types/scanner.ts';

export interface WpScanApiResult {
  vulnerabilities: KnownVulnerability[];
  source: WpScanIntelligenceSource;
}

/**
 * Queries WPScan API if user or environment has provided an API key.
 * Otherwise, falls back to the curated WP Sentinel Intelligence Catalog.
 */
export async function fetchVulnerabilitiesForComponent(
  type: 'core' | 'plugin' | 'theme',
  slug: string,
  version?: string,
  apiKey?: string
): Promise<WpScanApiResult> {
  const token = apiKey || process.env.WPSCAN_API_KEY;

  if (token) {
    try {
      let endpoint = '';
      if (type === 'core' && version) {
        const cleanVer = version.replace(/[^0-9.]/g, '').replace(/\./g, '');
        endpoint = `https://wpscan.com/api/v3/wordpresses/${cleanVer}`;
      } else if (type === 'plugin') {
        endpoint = `https://wpscan.com/api/v3/plugins/${encodeURIComponent(slug)}`;
      }

      if (endpoint) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 4000);

        const res = await fetch(endpoint, {
          headers: {
            'Authorization': `Token token=${token}`,
            'User-Agent': 'WPSentinel/1.0 (+https://wpsentinel.security)'
          },
          signal: controller.signal
        });
        clearTimeout(timeoutId);

        if (res.ok) {
          const data = await res.json() as Record<string, any>;
          const rawVulns = data[slug]?.vulnerabilities || data.vulnerabilities || [];
          
          const mapped: KnownVulnerability[] = rawVulns.map((v: any) => ({
            cveId: v.cve ? `CVE-${v.cve}` : (v.references?.cve ? `CVE-${v.references.cve[0]}` : 'WPScan-Intel'),
            title: v.title || `${slug} Security Flaw`,
            severity: (v.vuln_type === 'SQLI' || v.vuln_type === 'RCE' ? 'critical' : v.vuln_type === 'XSS' ? 'high' : 'medium') as FindingSeverity,
            cvssScore: v.cvss?.score || (v.vuln_type === 'RCE' ? 9.8 : 7.2),
            description: v.description || v.title,
            affectedVersions: v.fixed_in ? `< ${v.fixed_in}` : 'All versions prior to patch',
            fixedIn: v.fixed_in || 'Vendor Patch Required',
            references: [v.references?.url?.[0] || 'https://wpscan.com']
          }));

          return {
            vulnerabilities: mapped,
            source: {
              usedLiveApi: true,
              apiKeyConfigured: true,
              statusMessage: 'Live WPScan Threat Intelligence API connected successfully.',
              vulnCount: mapped.length
            }
          };
        }
      }
    } catch (err) {
      console.warn('WPScan API query failed, falling back to curated intelligence database', err);
    }
  }

  // Fallback to built-in curated catalog
  const catalogVulns = queryCatalog(slug, version);
  return {
    vulnerabilities: catalogVulns,
    source: {
      usedLiveApi: false,
      apiKeyConfigured: Boolean(token),
      statusMessage: token
        ? 'WPScan API unreachable; utilized WP Sentinel Curated CVE Intelligence Catalog.'
        : 'WPScan API key not configured. Using WP Sentinel Curated WordPress Intelligence Catalog (NIST & WPScan synced).',
      vulnCount: catalogVulns.length
    }
  };
}
