/**
 * RDAP (Registration Data Access Protocol) Domain Analysis Service
 *
 * Queries authoritative RDAP registries to fetch real domain registration data:
 * - Domain name
 * - Registrar
 * - Creation / Registration date
 * - Expiration date
 * - Last updated date
 * - Domain status codes
 * - Calculated domain age in days
 *
 * Implements bootstrap routing with fallback servers for major TLDs.
 */

export interface RdapResult {
  available: boolean;
  domain?: string;
  registrar?: string | null;
  createdAt?: string | null;
  updatedAt?: string | null;
  expiresAt?: string | null;
  status?: string[];
  ageDays?: number | null;
  ageFormatted?: string | null;
  error?: string;
}

// Built-in authoritative RDAP base URLs for common TLDs (RFC 9082/9083)
const KNOWN_RDAP_BASES: Record<string, string> = {
  com: 'https://rdap.verisign.com/com/v1/',
  net: 'https://rdap.verisign.com/net/v1/',
  org: 'https://rdap.publicinterestregistry.net/rdap/org/',
  info: 'https://rdap.identitydigital.services/rdap/',
  biz: 'https://rdap.nic.biz/',
  io: 'https://rdap.nic.io/',
  co: 'https://rdap.nic.co/',
  me: 'https://rdap.nic.me/',
  app: 'https://rdap.nic.google/',
  dev: 'https://rdap.nic.google/',
  page: 'https://rdap.nic.google/',
  xyz: 'https://rdap.nic.xyz/',
  club: 'https://rdap.identitydigital.services/rdap/',
  live: 'https://rdap.identitydigital.services/rdap/',
  tech: 'https://rdap.radix.net/rdap/',
  online: 'https://rdap.radix.net/rdap/',
  site: 'https://rdap.radix.net/rdap/',
  store: 'https://rdap.radix.net/rdap/',
  top: 'https://rdap.nic.top/',
  cloud: 'https://rdap.nic.cloud/',
  us: 'https://rdap.nic.us/',
  ca: 'https://rdap.ca.fury.ca/rdap/',
  de: 'https://rdap.denic.de/',
  fr: 'https://rdap.nic.fr/',
  nl: 'https://rdap.sidn.nl/',
  br: 'https://rdap.registro.br/',
  au: 'https://rdap.auda.org.au/',
  uk: 'https://rdap.nominet.uk/',
};

// In-memory cache of IANA bootstrap data
let ianaBootstrapCache: Array<[string[], string[]]> | null = null;
let lastBootstrapFetch = 0;

/**
 * Fetch and cache IANA RDAP bootstrap data
 */
async function getIanaBootstrap(): Promise<Array<[string[], string[]]>> {
  const now = Date.now();
  if (ianaBootstrapCache && now - lastBootstrapFetch < 3600000) {
    return ianaBootstrapCache;
  }

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 4000);
    const res = await fetch('https://data.iana.org/rdap/dns.json', {
      signal: controller.signal,
      headers: { 'Accept': 'application/json' }
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      if (Array.isArray(data.services)) {
        ianaBootstrapCache = data.services;
        lastBootstrapFetch = now;
        return data.services;
      }
    }
  } catch {
    // Fail silently to fallbacks if IANA is unreachable
  }

  return ianaBootstrapCache || [];
}

/**
 * Extract apex / registrable domain from a hostname
 * e.g. "www.example.com" -> "example.com"
 * e.g. "api.stripe.com" -> "stripe.com"
 * e.g. "portal.service.co.uk" -> "service.co.uk"
 */
export function extractApexDomain(hostname: string): { apex: string; tld: string } {
  const cleaned = hostname.toLowerCase().trim().replace(/\.$/, '');
  const parts = cleaned.split('.');

  if (parts.length <= 1) {
    return { apex: cleaned, tld: '' };
  }

  // Common second-level TLDs
  const secondLevelTlds = new Set([
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk',
    'com.au', 'net.au', 'org.au', 'edu.au',
    'co.nz', 'net.nz', 'org.nz',
    'co.jp', 'ne.jp', 'or.jp',
    'com.br', 'org.br', 'net.br',
    'com.mx', 'org.mx',
    'co.za', 'org.za',
    'co.in', 'net.in', 'org.in',
    'com.sg', 'edu.sg'
  ]);

  if (parts.length >= 3) {
    const lastTwo = parts.slice(-2).join('.');
    if (secondLevelTlds.has(lastTwo)) {
      const apex = parts.slice(-3).join('.');
      return { apex, tld: lastTwo };
    }
  }

  const apex = parts.slice(-2).join('.');
  const tld = parts[parts.length - 1];
  return { apex, tld };
}

/**
 * Resolve the authoritative RDAP server URL for a given TLD
 */
async function resolveRdapServerForTld(tld: string): Promise<string | null> {
  const normalizedTld = tld.toLowerCase().trim();

  // Check known map first
  if (KNOWN_RDAP_BASES[normalizedTld]) {
    return KNOWN_RDAP_BASES[normalizedTld];
  }

  // Check IANA bootstrap
  const services = await getIanaBootstrap();
  for (const [tlds, servers] of services) {
    if (tlds.includes(normalizedTld) && servers.length > 0) {
      let server = servers[0];
      if (!server.endsWith('/')) server += '/';
      return server;
    }
  }

  return null;
}

/**
 * Calculate age in days and readable string
 */
function calculateDomainAge(createdAtIso: string): { days: number; formatted: string } | null {
  try {
    const createdTime = new Date(createdAtIso).getTime();
    if (Number.isNaN(createdTime)) return null;

    const diffMs = Date.now() - createdTime;
    if (diffMs < 0) return null;

    const days = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    const years = (days / 365.25).toFixed(1);

    let formatted = `${days} days`;
    if (days >= 365) {
      formatted = `${years} years (${days.toLocaleString()} days)`;
    } else if (days >= 30) {
      const months = Math.floor(days / 30.4);
      formatted = `${months} months (${days} days)`;
    }

    return { days, formatted };
  } catch {
    return null;
  }
}

/**
 * Perform real RDAP lookup for a hostname
 */
export async function queryDomainRdap(hostname: string): Promise<RdapResult> {
  const { apex, tld } = extractApexDomain(hostname);
  if (!apex || !tld) {
    return { available: false, error: 'Invalid domain name structure' };
  }

  const rdapBaseUrl = await resolveRdapServerForTld(tld);
  if (!rdapBaseUrl) {
    return {
      available: false,
      domain: apex,
      error: `RDAP server not published by registry for .${tld}`
    };
  }

  const requestUrl = `${rdapBaseUrl}domain/${encodeURIComponent(apex)}`;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000); // 5-second timeout

  try {
    const response = await fetch(requestUrl, {
      method: 'GET',
      headers: {
        'Accept': 'application/rdap+json, application/json',
        'User-Agent': 'VERISCAN-Trust-Analyzer/1.0 (+https://veriscan.ai; RDAP client)'
      },
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (response.status === 404) {
      return {
        available: false,
        domain: apex,
        error: 'Domain not found in authoritative RDAP registry (may be unregistered or private)'
      };
    }

    if (!response.ok) {
      return {
        available: false,
        domain: apex,
        error: `RDAP server responded with HTTP status ${response.status}`
      };
    }

    const data = await response.json();

    // 1. Extract Registrar
    let registrar: string | null = null;
    if (Array.isArray(data.entities)) {
      const registrarEntity = data.entities.find((e: any) =>
        Array.isArray(e.roles) && e.roles.includes('registrar')
      );
      if (registrarEntity) {
        if (Array.isArray(registrarEntity.vcardArray) && Array.isArray(registrarEntity.vcardArray[1])) {
          const fnProp = registrarEntity.vcardArray[1].find((prop: any) => Array.isArray(prop) && prop[0] === 'fn');
          if (fnProp && typeof fnProp[3] === 'string' && fnProp[3].trim()) {
            registrar = fnProp[3].trim();
          }
        }
        if (!registrar && registrarEntity.handle) {
          registrar = String(registrarEntity.handle);
        }
      }
    }

    // 2. Extract Event Dates
    let createdAt: string | null = null;
    let updatedAt: string | null = null;
    let expiresAt: string | null = null;

    if (Array.isArray(data.events)) {
      for (const ev of data.events) {
        if (!ev || typeof ev !== 'object') continue;
        const action = String(ev.eventAction || '').toLowerCase();
        const date = ev.eventDate;

        if (!date) continue;

        if (action === 'registration' || action === 'created' || action === 'registered') {
          createdAt = date;
        } else if (action === 'expiration' || action === 'expired') {
          expiresAt = date;
        } else if (action === 'last changed' || action === 'last update' || action === 'updated') {
          updatedAt = date;
        }
      }
    }

    // 3. Extract Status list
    const status: string[] = Array.isArray(data.status) ? data.status.map(String) : [];

    // 4. Calculate Age
    let ageDays: number | null = null;
    let ageFormatted: string | null = null;
    if (createdAt) {
      const ageCalc = calculateDomainAge(createdAt);
      if (ageCalc) {
        ageDays = ageCalc.days;
        ageFormatted = ageCalc.formatted;
      }
    }

    const verifiedDomain = (typeof data.ldhName === 'string' && data.ldhName) ? data.ldhName.toLowerCase() : apex;

    return {
      available: true,
      domain: verifiedDomain,
      registrar: registrar || null,
      createdAt: createdAt || null,
      updatedAt: updatedAt || null,
      expiresAt: expiresAt || null,
      status,
      ageDays,
      ageFormatted
    };
  } catch (err: any) {
    clearTimeout(timeoutId);
    let msg = 'RDAP query failed';
    if (err.name === 'AbortError') {
      msg = 'RDAP registry query timed out after 5 seconds';
    } else if (err.message) {
      msg = err.message;
    }

    return {
      available: false,
      domain: apex,
      error: msg
    };
  }
}
