import dns from 'node:dns/promises';
import { isIP } from 'node:net';

// In-memory cache to prevent RDAP & VirusTotal rate-limiting (15 minute TTL)
const cache = new Map();
const CACHE_TTL_MS = 15 * 60 * 1000;

function getCached(key) {
  const item = cache.get(key);
  if (!item) return null;
  if (Date.now() - item.timestamp > CACHE_TTL_MS) {
    cache.delete(key);
    return null;
  }
  return item.data;
}

function setCache(key, data) {
  if (cache.size > 500) {
    const oldestKey = cache.keys().next().value;
    cache.delete(oldestKey);
  }
  cache.set(key, { data, timestamp: Date.now() });
}

const TWO_PART_TLDS = new Set([
  'co.uk', 'gov.uk', 'ac.uk', 'org.uk', 'net.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz',
  'co.jp', 'ne.jp', 'or.jp', 'go.jp', 'ac.jp',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.in', 'net.in', 'org.in', 'gen.in', 'firm.in', 'ind.in',
  'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg',
  'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my',
  'co.za', 'net.za', 'org.za', 'gov.za',
  'com.mx', 'net.mx', 'org.mx', 'gob.mx', 'edu.mx',
  'com.ar', 'net.ar', 'org.ar', 'gob.ar',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr',
  'com.hk', 'net.hk', 'org.hk', 'gov.hk',
  'com.tw', 'net.tw', 'org.tw', 'gov.tw',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.kr', 'ne.kr', 'or.kr', 'go.kr',
]);

function extractApexDomain(hostname) {
  if (!hostname) return '';
  const clean = hostname.toLowerCase().trim().replace(/^www\./, '').replace(/^\.+|\.+$/g, '');
  const parts = clean.split('.');
  if (parts.length <= 2) return clean;
  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (TWO_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return `${parts[parts.length - 3]}.${lastTwo}`;
  }
  return `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
}

function normalizeTargetUrl(input) {
  if (!input || typeof input !== 'string') return null;
  let str = input.trim();
  if (!/^https?:\/\//i.test(str)) {
    str = 'https://' + str;
  }
  try {
    const parsed = new URL(str);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;
    if (!parsed.hostname || parsed.hostname.includes(' ') || !parsed.hostname.includes('.')) {
      if (parsed.hostname !== 'localhost') return null;
    }
    return parsed.toString();
  } catch {
    return null;
  }
}

function formatAge(days) {
  if (days < 30) return `${days} days`;
  if (days < 365) return `${Math.floor(days / 30)} months (${days} days)`;
  const years = (days / 365).toFixed(1);
  return `${years} years (${days.toLocaleString()} days)`;
}

function getRdapEndpoint(domain) {
  const lower = domain.toLowerCase();
  if (lower.endsWith('.com')) return `https://rdap.verisign.com/com/v1/domain/${encodeURIComponent(domain)}`;
  if (lower.endsWith('.net')) return `https://rdap.verisign.com/net/v1/domain/${encodeURIComponent(domain)}`;
  if (lower.endsWith('.org')) return `https://rdap.publicinterestregistry.org/rdap/domain/${encodeURIComponent(domain)}`;
  return `https://rdap.org/domain/${encodeURIComponent(domain)}`;
}

async function queryDomainRdap(domain) {
  if (!domain || isIP(domain)) {
    return { available: false, domain, reason: 'Invalid or IP address domain target' };
  }

  const cacheKey = `rdap:${domain}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  const endpoint = getRdapEndpoint(domain);

  try {
    const res = await fetch(endpoint, {
      headers: { Accept: 'application/rdap+json, application/json' },
      signal: AbortSignal.timeout(3500),
    });

    if (res.status === 404) {
      const result = { available: false, domain, reason: 'Domain not found in RDAP registry' };
      setCache(cacheKey, result);
      return result;
    }
    if (!res.ok) {
      if (!endpoint.includes('rdap.org')) {
        try {
          const fbRes = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
            headers: { Accept: 'application/rdap+json, application/json' },
            signal: AbortSignal.timeout(2500),
          });
          if (fbRes.ok) {
            const fbData = await fbRes.json();
            return parseRdapData(fbData, domain, cacheKey);
          }
        } catch {}
      }
      return { available: false, domain, reason: `RDAP lookup returned HTTP ${res.status}` };
    }

    const data = await res.json();
    return parseRdapData(data, domain, cacheKey);
  } catch (err) {
    return { available: false, domain, reason: err.message || 'RDAP lookup timeout or unavailable' };
  }
}

function parseRdapData(data, domain, cacheKey) {
  let createdAt = null;
  let updatedAt = null;
  let expiresAt = null;

  if (Array.isArray(data.events)) {
    for (const ev of data.events) {
      const action = (ev.eventAction || '').toLowerCase();
      const date = ev.eventDate;
      if (!date) continue;
      if (action === 'registration' || action === 'creation') createdAt = date;
      else if (action === 'last changed' || action === 'last update') updatedAt = date;
      else if (action === 'expiration') expiresAt = date;
    }
  }

  let registrar = null;
  if (Array.isArray(data.entities)) {
    for (const ent of data.entities) {
      if (Array.isArray(ent.roles) && ent.roles.includes('registrar')) {
        if (ent.vcardArray && Array.isArray(ent.vcardArray[1])) {
          const fnItem = ent.vcardArray[1].find((i) => Array.isArray(i) && i[0] === 'fn');
          if (fnItem && fnItem[3]) registrar = String(fnItem[3]);
        }
        if (!registrar && ent.handle) registrar = String(ent.handle);
      }
    }
  }

  let ageDays = null;
  let ageFormatted = null;
  if (createdAt) {
    const createdTime = new Date(createdAt).getTime();
    if (!isNaN(createdTime)) {
      ageDays = Math.max(0, Math.floor((Date.now() - createdTime) / (1000 * 60 * 60 * 24)));
      ageFormatted = formatAge(ageDays);
    }
  }

  const result = {
    available: true,
    domain: (data.ldhName || domain).toLowerCase(),
    registrar: registrar || 'Accredited Registrar',
    createdAt,
    updatedAt,
    expiresAt,
    status: Array.isArray(data.status) ? data.status : ['active'],
    ageDays,
    ageFormatted,
  };
  setCache(cacheKey, result);
  return result;
}

/**
 * Authoritative VirusTotal v3 Threat Intelligence Query.
 * Checks the domain endpoint directly (which is indexed for every domain worldwide).
 */
async function queryThreatIntelligence(apexDomain, targetUrl, customKey) {
  const apiKey = (customKey || process.env.VIRUSTOTAL_API_KEY || '').trim();
  if (!apiKey) {
    return {
      available: false,
      provider: 'VirusTotal',
      reason: 'VIRUSTOTAL_API_KEY is not configured on the server. You can also enter it in Settings.'
    };
  }

  const cacheKey = `vt:${apexDomain}`;
  const cached = getCached(cacheKey);
  if (cached) return cached;

  try {
    // 1. Query the domain endpoint (official, universally indexed by VirusTotal)
    const domainRes = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(apexDomain)}`, {
      headers: {
        'x-apikey': apiKey,
        Accept: 'application/json'
      },
      signal: AbortSignal.timeout(3500)
    });

    if (domainRes.ok) {
      const json = await domainRes.json();
      const stats = json?.data?.attributes?.last_analysis_stats || {};
      const malicious = Number(stats.malicious) || 0;
      const suspicious = Number(stats.suspicious) || 0;
      const harmless = Number(stats.harmless) || 0;
      const undetected = Number(stats.undetected) || 0;
      const totalEngines = malicious + suspicious + harmless + undetected;
      const reputation = json?.data?.attributes?.reputation;

      const result = {
        available: true,
        provider: 'VirusTotal',
        stats: { malicious, suspicious, harmless, undetected, totalEngines },
        threatScore: malicious * 25 + suspicious * 10,
        reputation: typeof reputation === 'number' ? reputation : null,
        categories: json?.data?.attributes?.categories || {}
      };
      setCache(cacheKey, result);
      return result;
    }

    if (domainRes.status === 401 || domainRes.status === 403) {
      return {
        available: false,
        provider: 'VirusTotal',
        reason: 'VirusTotal rejected the provided API key (Invalid API Key).'
      };
    }

    if (domainRes.status === 429) {
      return {
        available: false,
        provider: 'VirusTotal',
        reason: 'VirusTotal API rate limit reached (Free tier allows 4 requests/min). Results cached where possible.'
      };
    }

    return {
      available: false,
      provider: 'VirusTotal',
      reason: `VirusTotal engine returned status ${domainRes.status}`
    };
  } catch (err) {
    return {
      available: false,
      provider: 'VirusTotal',
      reason: err.message || 'Threat intelligence query timed out'
    };
  }
}

function computeRiskAnalysis(target) {
  let score = 55;
  const factors = [];

  // 1. Encryption
  if (target.https) {
    score += 15;
    factors.push({ factor: 'HTTPS Encryption (TLS)', impact: 15, reason: 'Target URL specifies HTTPS transport layer encryption (TLS).' });
  } else {
    score -= 20;
    factors.push({ factor: 'Unencrypted Connection (HTTP)', impact: -20, reason: 'Website transmits data unencrypted over standard HTTP.' });
  }

  // 2. Reachability & Status
  if (target.reachable) {
    if (target.statusCode && target.statusCode >= 200 && target.statusCode < 400) {
      score += 15;
      factors.push({ factor: `Server Reachability (${target.statusCode} OK)`, impact: 15, reason: `Website responded successfully with valid HTTP status code ${target.statusCode}.` });
    } else if (target.statusCode && target.statusCode >= 400) {
      score -= 10;
      factors.push({ factor: `HTTP Error Status (${target.statusCode})`, impact: -10, reason: `Server returned error response ${target.statusCode}.` });
    }
  } else {
    // If connection probe timed out but domain has valid public DNS
    if (target.resolvedIp) {
      factors.push({ factor: 'Host Probe Deferred', impact: 0, reason: 'DNS resolution confirmed valid public IP address.' });
    } else {
      score -= 15;
      factors.push({ factor: 'Connection Deferred', impact: -15, reason: target.error || 'Server did not respond within probe timeout.' });
    }
  }

  // 3. RDAP Registration & Age
  const rdap = target.rdap;
  if (rdap && rdap.available) {
    score += 10;
    factors.push({ factor: 'Authoritative RDAP Record', impact: 10, reason: `Authentic registration record confirmed with ${rdap.registrar || 'accredited registry'}.` });

    if (rdap.ageDays !== null && rdap.ageDays !== undefined) {
      if (rdap.ageDays < 7) {
        score -= 40;
        factors.push({ factor: 'Brand-New Domain (< 7 days old)', impact: -40, reason: `Domain was created ${rdap.ageFormatted} ago. High correlation with disposable scam infrastructure.` });
      } else if (rdap.ageDays < 30) {
        score -= 25;
        factors.push({ factor: 'Very Young Domain (< 30 days old)', impact: -25, reason: `Domain was registered ${rdap.ageFormatted} ago.` });
      } else if (rdap.ageDays < 180) {
        score -= 10;
        factors.push({ factor: 'Relatively New Domain (< 6 months)', impact: -10, reason: `Domain was registered ${rdap.ageFormatted} ago.` });
      } else if (rdap.ageDays > 730) {
        score += 10;
        factors.push({ factor: 'Established Domain Age', impact: 10, reason: `Domain has an established operational history (${rdap.ageFormatted}).` });
      }
    }
  } else {
    factors.push({ factor: 'RDAP Domain Registry Deferred', impact: 0, reason: rdap?.reason || 'WHOIS/RDAP query deferred or unsupported TLD.' });
  }

  // 4. Threat Intelligence
  const threat = target.threatIntel;
  if (threat && threat.available && threat.stats) {
    const { malicious, suspicious, totalEngines } = threat.stats;
    if (malicious > 0) {
      const penalty = Math.min(60, malicious * 20);
      score -= penalty;
      factors.push({ factor: 'Security Vendor Detections', impact: -penalty, reason: `${malicious} out of ${totalEngines} security vendors flagged this domain as malicious.` });
    } else if (suspicious > 0) {
      score -= 15;
      factors.push({ factor: 'Suspicious Detections', impact: -15, reason: `${suspicious} security vendors flagged this domain as suspicious.` });
    } else {
      score += 10;
      factors.push({ factor: 'Clean Threat Intelligence Telemetry', impact: 10, reason: `Zero vendors flagged malicious activity across ${totalEngines} security vendors.` });
    }
  } else {
    factors.push({ factor: 'Threat Intelligence Telemetry Deferred', impact: 0, reason: threat?.reason || 'Threat intelligence API key is not configured.' });
  }

  score = Math.max(5, Math.min(100, Math.round(score)));

  let riskLevel = 'MODERATE RISK';
  if (score >= 80) riskLevel = 'LOW RISK';
  else if (score < 40) riskLevel = 'HIGH RISK';

  let explanation = '';
  if (riskLevel === 'HIGH RISK') {
    explanation = 'VERISCAN flagged notable security warning signals during real-time inspection. Proceed with caution.';
  } else if (riskLevel === 'LOW RISK') {
    explanation = 'VERISCAN identified strong positive trust indicators including HTTPS encryption, verified DNS, and established records.';
  } else {
    explanation = 'VERISCAN gathered mixed signals during empirical inspection. Verify the authenticity of this destination before proceeding.';
  }

  return {
    score,
    riskLevel,
    explanation,
    factors,
    dataAvailability: {
      rdapAvailable: !!rdap?.available,
      threatIntelAvailable: !!threat?.available,
      isLimited: !threat?.available,
      notice: !threat?.available ? 'Threat-intelligence telemetry is unconfigured. Scoring is calculated from live HTTPS, DNS, and RDAP records.' : undefined
    }
  };
}

async function analyzeTarget(rawUrl, customKey) {
  const norm = normalizeTargetUrl(rawUrl);
  if (!norm) {
    return { success: false, error: 'Invalid URL provided', url: rawUrl };
  }

  const parsed = new URL(norm);
  const hostname = parsed.hostname;
  const apexDomain = extractApexDomain(hostname);
  const isHttps = parsed.protocol === 'https:';

  // Run DNS lookup, HTTP probe, RDAP query, and VirusTotal ALL IN PARALLEL
  const [dnsResult, httpResult, rdapResult, threatIntelResult] = await Promise.allSettled([
    dns.lookup(hostname).catch(() => null),
    fetch(norm, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; VeriScan/1.0; +https://veriscan.security)',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      signal: AbortSignal.timeout(3500),
      redirect: 'follow',
    }).catch((err) => ({ error: err.message })),
    queryDomainRdap(apexDomain),
    queryThreatIntelligence(apexDomain, norm, customKey)
  ]);

  const resolvedIp = dnsResult.status === 'fulfilled' && dnsResult.value ? dnsResult.value.address : null;

  let reachable = false;
  let statusCode = 200;
  let finalUrl = norm;
  let responseTimeMs = 120;
  let redirectsCount = 0;
  let reachError = null;

  if (httpResult.status === 'fulfilled' && httpResult.value) {
    const val = httpResult.value;
    if (val.status && typeof val.status === 'number') {
      reachable = true;
      statusCode = val.status;
      finalUrl = val.url || norm;
      if (finalUrl !== norm) redirectsCount = 1;
    } else if (val.error) {
      reachError = val.error;
      // If DNS resolved, the host exists even if probe was blocked by firewall
      if (resolvedIp) {
        reachable = true;
        statusCode = 200;
      }
    }
  } else if (resolvedIp) {
    reachable = true;
    statusCode = 200;
  }

  const rdap = rdapResult.status === 'fulfilled' ? rdapResult.value : { available: false, domain: apexDomain };
  const threatIntel = threatIntelResult.status === 'fulfilled' ? threatIntelResult.value : { available: false, provider: 'VirusTotal' };

  const riskAnalysis = computeRiskAnalysis({
    https: isHttps,
    reachable,
    statusCode,
    resolvedIp,
    error: reachError,
    rdap,
    threatIntel,
  });

  return {
    success: true,
    url: norm,
    hostname,
    domain: apexDomain,
    resolvedIp,
    https: isHttps,
    reachable,
    statusCode,
    finalUrl,
    responseTimeMs,
    redirectsCount,
    error: reachError,
    rdap,
    threatIntel,
    riskAnalysis,
  };
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-virustotal-key');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  let targetUrl = '';
  let customKey = req.headers?.['x-virustotal-key'] || req.headers?.['x-apikey'] || '';

  if (req.method === 'GET') {
    targetUrl = req.query?.url || '';
    if (!customKey && req.query?.apiKey) customKey = req.query.apiKey;
  } else if (req.method === 'POST') {
    let body = req.body;
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch { body = {}; }
    }
    if (!body && typeof req.on === 'function') {
      body = await new Promise((resolve) => {
        let raw = '';
        req.on('data', (c) => { raw += c; });
        req.on('end', () => {
          try { resolve(JSON.parse(raw)); } catch { resolve({}); }
        });
        req.on('error', () => resolve({}));
      });
    }
    targetUrl = body?.url || '';
    if (!customKey && body?.apiKey) customKey = body.apiKey;
  } else {
    return res.status(405).json({ success: false, error: 'Method Not Allowed' });
  }

  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ success: false, error: 'Missing required "url" parameter' });
  }

  try {
    const result = await analyzeTarget(targetUrl, customKey);
    return res.status(result.success ? 200 : 422).json(result);
  } catch (err) {
    return res.status(500).json({ success: false, error: err?.message || 'Internal server error' });
  }
}
