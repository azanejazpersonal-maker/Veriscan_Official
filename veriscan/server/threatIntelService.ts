/**
 * Threat-Intelligence Analysis Service
 * 
 * Securely queries VirusTotal API v3 on the server side using the
 * VIRUSTOTAL_API_KEY environment variable.
 * 
 * Never exposes the API key to the client.
 * Never fabricates results or treats unavailable API data as proof of safety.
 */

export interface ThreatIntelResult {
  available: boolean;
  provider: string;
  malicious?: number | null;
  suspicious?: number | null;
  harmless?: number | null;
  undetected?: number | null;
  totalEngines?: number | null;
  reputation?: number | null;
  reason?: string;
}

export async function queryThreatIntelligence(domainOrHost: string): Promise<ThreatIntelResult> {
  const apiKey = (process.env.VIRUSTOTAL_API_KEY || '').trim();

  // 1. If no API key is configured, return clean unavailable state
  if (!apiKey) {
    return {
      available: false,
      provider: 'VirusTotal',
      reason: 'Threat-intelligence analysis unavailable (VIRUSTOTAL_API_KEY is not configured on the server).'
    };
  }

  // Clean the target domain
  const cleanDomain = domainOrHost
    .toLowerCase()
    .trim()
    .replace(/^https?:\/\//, '')
    .split('/')[0]
    .replace(/^www\./, '');

  if (!cleanDomain || !cleanDomain.includes('.')) {
    return {
      available: false,
      provider: 'VirusTotal',
      reason: 'Invalid domain name structure for threat analysis.'
    };
  }

  const endpoint = `https://www.virustotal.com/api/v3/domains/${encodeURIComponent(cleanDomain)}`;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 6000); // 6s timeout

  try {
    const response = await fetch(endpoint, {
      method: 'GET',
      headers: {
        'x-apikey': apiKey,
        'Accept': 'application/json',
        'User-Agent': 'VERISCAN-Trust-Analyzer/1.0 (+https://veriscan.ai)'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    // Domain not found in VirusTotal database yet
    if (response.status === 404) {
      return {
        available: true,
        provider: 'VirusTotal',
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        totalEngines: 0,
        reputation: 0,
        reason: 'Domain has no historical scan telemetry in the VirusTotal database.'
      };
    }

    // Rate limit hit (Free tier allows 4 requests/min)
    if (response.status === 429) {
      return {
        available: false,
        provider: 'VirusTotal',
        reason: 'VirusTotal API rate limit reached (free tier allows 4 requests/minute). Try again in a moment.'
      };
    }

    // Invalid or unauthorized key
    if (response.status === 401 || response.status === 403) {
      return {
        available: false,
        provider: 'VirusTotal',
        reason: 'Invalid or restricted VirusTotal API key configured on server.'
      };
    }

    if (!response.ok) {
      return {
        available: false,
        provider: 'VirusTotal',
        reason: `VirusTotal API responded with status ${response.status}.`
      };
    }

    const json = await response.json();
    const attributes = json?.data?.attributes;

    if (!attributes) {
      return {
        available: false,
        provider: 'VirusTotal',
        reason: 'Malformed payload received from VirusTotal API.'
      };
    }

    const stats = attributes.last_analysis_stats || {};
    const malicious = Number(stats.malicious || 0);
    const suspicious = Number(stats.suspicious || 0);
    const harmless = Number(stats.harmless || 0);
    const undetected = Number(stats.undetected || 0);
    const timeout = Number(stats.timeout || 0);
    const totalEngines = malicious + suspicious + harmless + undetected + timeout;

    return {
      available: true,
      provider: 'VirusTotal',
      malicious,
      suspicious,
      harmless,
      undetected,
      totalEngines,
      reputation: typeof attributes.reputation === 'number' ? attributes.reputation : null
    };
  } catch (err: any) {
    clearTimeout(timeoutId);
    let msg = 'Failed to connect to threat intelligence service.';
    if (err.name === 'AbortError') {
      msg = 'VirusTotal API request timed out after 6 seconds.';
    } else if (err.message) {
      msg = `VirusTotal network error: ${err.message}`;
    }

    return {
      available: false,
      provider: 'VirusTotal',
      reason: msg
    };
  }
}
