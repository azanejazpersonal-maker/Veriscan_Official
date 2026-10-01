import dns from 'node:dns/promises';
import { isIP } from 'node:net';

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
  const clean = hostname.toLowerCase().trim().replace(/^\.+|\.+$/g, '');
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

async function queryDomainRdap(domain) {
  if (!domain || isIP(domain)) {
    return { available: false, domain, reason: 'Invalid or IP address domain target' };
  }
  try {
    const res = await fetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: 'application/rdap+json, application/json' },
      signal: AbortSignal.timeout(6000),
    });

    if (res.status === 404) {
      return { available: false, domain, reason: 'Domain not found in RDAP registry' };
    }
    if (!res.ok) {
      return { available: false, domain, reason: `RDAP lookup returned HTTP ${res.status}` };
    }

    const data = await res.json();
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

    return {
      available: true,
      domain: (data.ldhName || domain).toLowerCase(),
      registrar,
      createdAt,
      updatedAt,
      expiresAt,
      status: Array.isArray(data.status) ? data.status : [],
      ageDays,
      ageFormatted,
    };
  } catch (err) {
    return { available: false, domain, reason: err.message || 'RDAP lookup failed' };
  }
}

async function queryThreatIntelligence(targetUrl) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey || apiKey.trim() === '') {
    return {
      available: false,
      provider: 'VirusTotal',
      reason: 'Threat-intelligence analysis unavailable (VIRUSTOTAL_API_KEY is not configured on the server).'
    };
  }

  try {
    const urlId = Buffer.from(targetUrl).toString('base64').replace(/=/g, '');
    const res = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: {
        'x-apikey': apiKey.trim(),
        Accept: 'application/json'
      },
      signal: AbortSignal.timeout(6000)
    });

    if (res.status === 404) {
      return {
        available: false,
        provider: 'VirusTotal',
        reason: 'Target URL is not currently indexed in the threat intelligence cache.'
      };
    }

    if (!res.ok) {
      return {
        available: false,
        provider: 'VirusTotal',
        reason: `Threat engine API returned status ${res.status}`
      };
    }

    const json = await res.json();
    const stats = json?.data?.attributes?.last_analysis_stats || {};
    const malicious = Number(stats.malicious) || 0;
    const suspicious = Number(stats.suspicious) || 0;
    const harmless = Number(stats.harmless) || 0;
    const undetected = Number(stats.undetected) || 0;
    const totalEngines = malicious + suspicious + harmless + undetected;

    return {
      available: true,
      provider: 'VirusTotal',
      stats: { malicious, suspicious, harmless, undetected, totalEngines },
      threatScore: malicious * 25 + suspicious * 10,
      tags: Array.isArray(json?.data?.attributes?.tags) ? json.data.attributes.tags : []
    };
  } catch (err) {
    return {
      available: false,
      provider: 'VirusTotal',
      reason: err.message || 'Threat intelligence query failed'
    };
  }
}

function computeRiskAnalysis(target) {
  let score = 50;
  const factors = [];

  if (target.https) {
    score += 15;
    factors.push({ factor: 'HTTPS Encryption', impact: 15, reason: 'Target URL enforces HTTPS transport layer encryption (TLS).' });
  } else {
    score -= 25;
    factors.push({ factor: 'Unencrypted Connection (HTTP)', impact: -25, reason: 'Website transmits data unencrypted over standard HTTP.' });
  }

  if (target.reachable) {
    if (target.statusCode && target.statusCode >= 200 && target.statusCode < 300) {
      score += 15;
      factors.push({ factor: `Server Reachability (${target.statusCode} OK)`, impact: 15, reason: `Website responded successfully with standard HTTP status code ${target.statusCode}.` });
    } else if (target.statusCode && target.statusCode >= 400) {
      score -= 15;
      factors.push({ factor: `HTTP Error Status (${target.statusCode})`, impact: -15, reason: `Server returned client/server error response ${target.statusCode}.` });
    }
  } else {
    score -= 30;
    factors.push({ factor: 'Unreachable Host', impact: -30, reason: target.error || 'Server did not respond to standard HTTP connection requests.' });
  }

  const rdap = target.rdap;
  if (rdap && rdap.available) {
    score += 10;
    factors.push({ factor: 'Authoritative RDAP Record', impact: 10, reason: 'Authentic registration records confirmed via accredited registry.' });

    if (rdap.ageDays !== null && rdap.ageDays !== undefined) {
      if (rdap.ageDays < 7) {
        score -= 40;
        factors.push({ factor: 'Brand-New Domain (< 7 days old)', impact: -40, reason: `Domain was created ${rdap.ageFormatted} ago. High correlation with disposable phishing infrastructure.` });
      } else if (rdap.ageDays < 30) {
        score -= 25;
        factors.push({ factor: 'Very Young Domain (< 30 days old)', impact: -25, reason: `Domain was registered ${rdap.ageFormatted} ago.` });
      } else if (rdap.ageDays < 180) {
        score -= 10;
        factors.push({ factor: 'Relatively New Domain (< 6 months)', impact: -10, reason: `Domain was registered ${rdap.ageFormatted} ago.` });
      } else if (rdap.ageDays > 730) {
        score += 15;
        factors.push({ factor: 'Established Domain Age', impact: 15, reason: `Domain has an established operational history (${rdap.ageFormatted}).` });
      }
    }
  } else {
    factors.push({ factor: 'RDAP Domain Registry Inconclusive', impact: 0, reason: `Authoritative WHOIS/RDAP record was not returned: ${rdap?.reason || 'Lookup inconclusive'}.` });
  }

  const threat = target.threatIntel;
  if (threat && threat.available && threat.stats) {
    const { malicious, suspicious, totalEngines } = threat.stats;
    if (malicious > 0) {
      const penalty = Math.min(60, malicious * 20);
      score -= penalty;
      factors.push({ factor: 'Security Vendor Detections', impact: -penalty, reason: `${malicious} out of ${totalEngines} security vendors flagged this URL as malicious.` });
    } else if (suspicious > 0) {
      score -= 15;
      factors.push({ factor: 'Suspicious Detections', impact: -15, reason: `${suspicious} security vendors flagged this URL as suspicious.` });
    } else {
      score += 10;
      factors.push({ factor: 'Clean Threat Intelligence Telemetry', impact: 10, reason: `Zero vendors flagged malicious activity across ${totalEngines} security vendors.` });
    }
  } else {
    factors.push({ factor: 'Threat Intelligence Unavailable', impact: 0, reason: threat?.reason || 'External threat telemetry was not configured or unavailable.' });
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  let riskLevel = 'MODERATE RISK';
  if (score >= 80) riskLevel = 'LOW RISK';
  else if (score < 40) riskLevel = 'HIGH RISK';

  let explanation = '';
  if (riskLevel === 'HIGH RISK') {
    explanation = 'VERISCAN flagged multiple high-severity risk signals during real-time inspection. Proceed with caution.';
  } else if (riskLevel === 'LOW RISK') {
    explanation = 'VERISCAN identified multiple positive trust indicators including HTTPS encryption and established domain records.';
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
      notice: !threat?.available ? 'Threat-intelligence telemetry is unconfigured on the server. Analysis is based on real HTTP reachability and RDAP domain records.' : undefined
    }
  };
}

async function analyzeTarget(rawUrl) {
  const norm = normalizeTargetUrl(rawUrl);
  if (!norm) {
    return { success: false, error: 'Invalid URL provided', url: rawUrl };
  }

  const parsed = new URL(norm);
  const hostname = parsed.hostname;
  const apexDomain = extractApexDomain(hostname);
  const isHttps = parsed.protocol === 'https:';

  let resolvedIp = null;
  try {
    const dnsLookup = await dns.lookup(hostname);
    resolvedIp = dnsLookup.address;
  } catch {
    // DNS resolution failure will be reflected in reachability
  }

  let reachable = false;
  let statusCode = null;
  let finalUrl = norm;
  let responseTimeMs = null;
  let redirectsCount = 0;
  let reachError = null;

  const startTime = Date.now();
  try {
    const res = await fetch(norm, {
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; VeriScan/1.0; +https://veriscan.security)',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      signal: AbortSignal.timeout(8000),
      redirect: 'follow',
    });

    responseTimeMs = Date.now() - startTime;
    statusCode = res.status;
    reachable = true;
    finalUrl = res.url;
    if (finalUrl !== norm) {
      redirectsCount = 1;
    }
  } catch (err) {
    responseTimeMs = Date.now() - startTime;
    reachError = err.message || 'Connection failed';
  }

  const [rdap, threatIntel] = await Promise.all([
    queryDomainRdap(apexDomain),
    queryThreatIntelligence(norm),
  ]);

  const riskAnalysis = computeRiskAnalysis({
    https: isHttps,
    reachable,
    statusCode,
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

// Vercel Serverless Function Handler
export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  let targetUrl = '';
  if (req.method === 'GET') {
    targetUrl = req.query?.url || '';
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
  } else {
    return res.status(405).json({ success: false, error: 'Method Not Allowed' });
  }

  if (!targetUrl || typeof targetUrl !== 'string') {
    return res.status(400).json({ success: false, error: 'Missing required "url" parameter' });
  }

  try {
    const result = await analyzeTarget(targetUrl);
    return res.status(result.success ? 200 : 422).json(result);
  } catch (err) {
    return res.status(500).json({ success: false, error: err?.message || 'Internal server error' });
  }
}
