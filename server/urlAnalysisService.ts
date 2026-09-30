import dns from 'node:dns/promises';
import { isIP } from 'node:net';
import { queryDomainRdap, extractApexDomain, type RdapResult } from './rdapService.ts';
import { queryThreatIntelligence, type ThreatIntelResult } from './threatIntelService.ts';
import { computeRiskAnalysis, type RiskAnalysisResult } from './riskScoringService.ts';

export interface AnalysisResponse {
  success: boolean;
  url: string;
  hostname: string;
  domain?: string;
  https: boolean;
  reachable: boolean;
  statusCode?: number;
  finalUrl?: string;
  responseTimeMs?: number;
  redirectsCount?: number;
  rdap?: RdapResult;
  threatIntel?: ThreatIntelResult;
  riskAnalysis?: RiskAnalysisResult;
  error?: string;
}

// Check if an IPv4 address is in a private, loopback, or reserved range
function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) {
    return true; // Malformed IP treated as unsafe
  }

  const [b0, b1] = parts;

  // 0.0.0.0/8 (Current network)
  if (b0 === 0) return true;
  // 10.0.0.0/8 (Private network)
  if (b0 === 10) return true;
  // 127.0.0.0/8 (Loopback)
  if (b0 === 127) return true;
  // 169.254.0.0/16 (Link-local, AWS/GCP metadata e.g. 169.254.169.254)
  if (b0 === 169 && b1 === 254) return true;
  // 172.16.0.0/12 (Private network)
  if (b0 === 172 && b1 >= 16 && b1 <= 31) return true;
  // 192.168.0.0/16 (Private network)
  if (b0 === 192 && b1 === 168) return true;
  // 100.64.0.0/10 (Carrier-grade NAT)
  if (b0 === 100 && b1 >= 64 && b1 <= 127) return true;
  // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (Documentation/Test)
  if (b0 === 192 && b1 === 0 && parts[2] === 2) return true;
  // 224.0.0.0/4 (Multicast) & 240.0.0.0/4 (Reserved)
  if (b0 >= 224) return true;

  return false;
}

// Check if an IPv6 address is private, loopback, or reserved
function isPrivateIPv6(ip: string): boolean {
  const normalized = ip.toLowerCase();

  // Loopback & Unspecified
  if (normalized === '::1' || normalized === '::') return true;

  // Unique Local Address (fc00::/7)
  if (normalized.startsWith('fc') || normalized.startsWith('fd')) return true;

  // Link-Local (fe80::/10)
  if (normalized.startsWith('fe8') || normalized.startsWith('fe9') || 
      normalized.startsWith('fea') || normalized.startsWith('feb')) {
    return true;
  }

  // IPv4-mapped IPv6 (::ffff:192.0.2.128)
  if (normalized.includes('::ffff:')) {
    const ipv4Part = normalized.split(':').pop();
    if (ipv4Part && isIP(ipv4Part) === 4) {
      return isPrivateIPv4(ipv4Part);
    }
    return true;
  }

  return false;
}

function isRestrictedIP(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return isPrivateIPv4(ip);
  if (version === 6) return isPrivateIPv6(ip);
  return true; // Unknown IP format is restricted
}

// Validate hostname and resolve DNS to prevent SSRF
async function validateHostForSSRF(hostname: string): Promise<string | null> {
  const lowerHost = hostname.toLowerCase();

  // Reject local domain names
  if (
    lowerHost === 'localhost' ||
    lowerHost.endsWith('.localhost') ||
    lowerHost.endsWith('.local') ||
    lowerHost.endsWith('.internal') ||
    lowerHost.endsWith('.lan') ||
    lowerHost.endsWith('.home.arpa')
  ) {
    return 'Access to local or private network domains is prohibited';
  }

  // If host is already an IP address directly in URL
  if (isIP(lowerHost)) {
    if (isRestrictedIP(lowerHost)) {
      return 'Access to private, loopback, or internal IP addresses is prohibited';
    }
    return null;
  }

  // Perform DNS lookup to inspect resolved IPs
  try {
    const addresses = await dns.lookup(hostname, { all: true });
    if (!addresses || addresses.length === 0) {
      return 'Domain name could not be resolved in DNS';
    }

    for (const record of addresses) {
      if (isRestrictedIP(record.address)) {
        return `Domain resolves to a restricted internal IP address (${record.address})`;
      }
    }
  } catch (err: any) {
    return `DNS resolution failed: ${err.message || 'Domain not found'}`;
  }

  return null;
}

// Safely normalize user-provided URL
export function normalizeTargetUrl(input: string): { url: URL; normalizedString: string } | null {
  if (!input || typeof input !== 'string') return null;

  let trimmed = input.trim();
  if (!trimmed) return null;

  // Auto-prepend https:// if no scheme is provided
  if (!/^https?:\/\//i.test(trimmed)) {
    trimmed = 'https://' + trimmed;
  }

  try {
    const parsed = new URL(trimmed);

    // Only allow http and https
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }

    // Disallow credentials in URL
    if (parsed.username || parsed.password) {
      return null;
    }

    // Must have a valid hostname with at least one dot (unless valid IP)
    if (!parsed.hostname || (!parsed.hostname.includes('.') && !isIP(parsed.hostname))) {
      return null;
    }

    return {
      url: parsed,
      normalizedString: parsed.href
    };
  } catch {
    return null;
  }
}

/**
 * Main backend trust analysis service function.
 * Validates, checks SSRF, performs controlled HTTP request, and returns structured data.
 */
export async function analyzeTargetUrl(rawUrl: string): Promise<AnalysisResponse> {
  const normalized = normalizeTargetUrl(rawUrl);
  if (!normalized) {
    return {
      success: false,
      url: rawUrl || '',
      hostname: '',
      https: false,
      reachable: false,
      error: 'Invalid URL format. Please provide a valid HTTP or HTTPS address.'
    };
  }

  const { url, normalizedString } = normalized;
  const initialHostname = url.hostname;
  const isHttps = url.protocol === 'https:';

  // 1. Initial SSRF check on hostname
  const ssrfError = await validateHostForSSRF(initialHostname);
  if (ssrfError) {
    return {
      success: false,
      url: normalizedString,
      hostname: initialHostname,
      https: isHttps,
      reachable: false,
      error: ssrfError
    };
  }

  // 2. Concurrently initiate real RDAP lookup & threat-intelligence analysis
  const { apex } = extractApexDomain(initialHostname);
  const rdapPromise = queryDomainRdap(initialHostname).catch((err: any) => ({
    available: false,
    domain: apex,
    error: err?.message || 'RDAP lookup failed'
  }));

  const threatIntelPromise = queryThreatIntelligence(apex || initialHostname).catch((err: any) => ({
    available: false,
    provider: 'VirusTotal',
    reason: err?.message || 'Threat intelligence query failed'
  }));

  // 3. Controlled HTTP Request with safe redirect following
  const startTime = Date.now();
  let currentUrl = normalizedString;
  let redirectsCount = 0;
  const MAX_REDIRECTS = 5;

  try {
    while (redirectsCount <= MAX_REDIRECTS) {
      const currentParsed = new URL(currentUrl);

      // Verify each redirect target for SSRF
      const redirectSsrfError = await validateHostForSSRF(currentParsed.hostname);
      if (redirectSsrfError) {
        const [rdap, threatIntel] = await Promise.all([rdapPromise, threatIntelPromise]);
        return {
          success: false,
          url: normalizedString,
          hostname: initialHostname,
          domain: rdap.domain || apex,
          https: isHttps,
          reachable: false,
          rdap,
          threatIntel,
          error: `Redirect blocked: ${redirectSsrfError}`
        };
      }

      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000); // 6s timeout

      try {
        // We use GET with manual redirect handling to verify every redirect target
        const response = await fetch(currentUrl, {
          method: 'GET',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'User-Agent': 'VERISCAN-Trust-Analyzer/1.0 (+https://veriscan.ai; bot)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
          }
        });

        clearTimeout(timeoutId);

        // Cancel body download immediately to avoid downloading large files
        if (response.body) {
          try {
            await response.body.cancel();
          } catch {
            // Ignore cancel errors
          }
        }

        const statusCode = response.status;

        // Check if redirect
        if ([301, 302, 303, 307, 308].includes(statusCode)) {
          const location = response.headers.get('location');
          if (location && redirectsCount < MAX_REDIRECTS) {
            // Resolve relative or absolute redirect URL
            const resolvedRedirect = new URL(location, currentUrl).href;
            currentUrl = resolvedRedirect;
            redirectsCount++;
            continue;
          }
        }

        const responseTimeMs = Date.now() - startTime;
        const [rdap, threatIntel] = await Promise.all([rdapPromise, threatIntelPromise]);
        const domain = rdap.domain || apex;

        const riskAnalysis = computeRiskAnalysis({
          url: normalizedString,
          hostname: initialHostname,
          domain,
          https: isHttps,
          reachable: true,
          statusCode,
          finalUrl: currentUrl,
          redirectsCount,
          rdap,
          threatIntel
        });

        return {
          success: true,
          url: normalizedString,
          hostname: initialHostname,
          domain,
          https: isHttps,
          reachable: true,
          statusCode,
          finalUrl: currentUrl,
          responseTimeMs,
          redirectsCount,
          rdap,
          threatIntel,
          riskAnalysis
        };
      } finally {
        clearTimeout(timeoutId);
      }
    }

    const [rdap, threatIntel] = await Promise.all([rdapPromise, threatIntelPromise]);
    const domain = rdap.domain || apex;
    const riskAnalysis = computeRiskAnalysis({
      url: normalizedString,
      hostname: initialHostname,
      domain,
      https: isHttps,
      reachable: false,
      redirectsCount,
      rdap,
      threatIntel
    });

    return {
      success: false,
      url: normalizedString,
      hostname: initialHostname,
      domain,
      https: isHttps,
      reachable: false,
      rdap,
      threatIntel,
      riskAnalysis,
      error: 'Exceeded maximum redirect limit (too many redirects)'
    };
  } catch (err: any) {
    const responseTimeMs = Date.now() - startTime;
    let errorMessage = 'Target website could not be reached';

    if (err.name === 'AbortError') {
      errorMessage = 'Connection timed out after 6 seconds';
    } else if (err.code === 'ENOTFOUND') {
      errorMessage = 'Domain name does not exist or DNS lookup failed';
    } else if (err.code === 'ECONNREFUSED') {
      errorMessage = 'Connection refused by destination host';
    } else if (err.code === 'ECONNRESET') {
      errorMessage = 'Connection reset by destination host';
    } else if (err.message) {
      errorMessage = `Network error: ${err.message}`;
    }

    const [rdap, threatIntel] = await Promise.all([rdapPromise, threatIntelPromise]);
    const domain = rdap.domain || apex;
    const riskAnalysis = computeRiskAnalysis({
      url: normalizedString,
      hostname: initialHostname,
      domain,
      https: isHttps,
      reachable: false,
      rdap,
      threatIntel
    });

    return {
      success: false,
      url: normalizedString,
      hostname: initialHostname,
      domain,
      https: isHttps,
      reachable: false,
      responseTimeMs,
      rdap,
      threatIntel,
      riskAnalysis,
      error: errorMessage
    };
  }
}
