/**
 * VERISCAN Deterministic Risk Scoring & Analysis Engine
 * 
 * Combines empirical signals from:
 * 1. HTTP Connectivity & TLS/HTTPS Inspection
 * 2. Safe Redirect Traversal
 * 3. Authoritative RFC 9082/9083 RDAP Domain Registration & Age
 * 4. Real Threat Intelligence Telemetry (VirusTotal)
 * 
 * IMPORTANT:
 * - Deterministic, rule-based calculation.
 * - Every point adjustment carries an explicit factor and reason.
 * - Never claims a website is "safe" or a "scam".
 * - Never treats unavailable data as positive evidence or proof of fraud.
 */

import type { RdapResult } from './rdapService.ts';
import type { ThreatIntelResult } from './threatIntelService.ts';

export interface ScoreFactor {
  factor: string;
  impact: number;
  reason: string;
}

export interface RiskAnalysisResult {
  score: number;
  riskLevel: 'LOW RISK' | 'MEDIUM RISK' | 'HIGH RISK';
  explanation: string;
  factors: ScoreFactor[];
  dataAvailability: {
    rdapAvailable: boolean;
    threatIntelAvailable: boolean;
    isLimited: boolean;
    notice?: string;
  };
}

export interface ScoringInput {
  url: string;
  hostname: string;
  domain?: string;
  https: boolean;
  reachable: boolean;
  statusCode?: number;
  finalUrl?: string;
  redirectsCount?: number;
  rdap?: RdapResult;
  threatIntel?: ThreatIntelResult;
}

export function computeRiskAnalysis(input: ScoringInput): RiskAnalysisResult {
  const factors: ScoreFactor[] = [];
  let rawScore = 40; // Neutral baseline

  const {
    https,
    reachable,
    statusCode,
    redirectsCount = 0,
    rdap,
    threatIntel
  } = input;

  // 1. HTTPS Transport Encryption
  if (https) {
    factors.push({
      factor: 'HTTPS Encryption',
      impact: 15,
      reason: 'Target URL enforces HTTPS transport layer encryption (TLS).'
    });
    rawScore += 15;
  } else {
    factors.push({
      factor: 'Unencrypted HTTP',
      impact: -20,
      reason: 'Plain HTTP connection detected; data in transit is unencrypted and vulnerable to interception.'
    });
    rawScore -= 20;
  }

  // 2. Reachability & HTTP Status Code
  if (reachable) {
    if (statusCode === 200) {
      factors.push({
        factor: 'Server Reachability (200 OK)',
        impact: 15,
        reason: 'Website responded successfully with standard HTTP status code 200 OK.'
      });
      rawScore += 15;
    } else if (statusCode && statusCode >= 201 && statusCode < 400) {
      factors.push({
        factor: `Server Response (${statusCode})`,
        impact: 10,
        reason: `Website acknowledged request with valid HTTP status code ${statusCode}.`
      });
      rawScore += 10;
    } else if (statusCode && statusCode >= 400 && statusCode < 500) {
      factors.push({
        factor: `Client Error (${statusCode})`,
        impact: -10,
        reason: `Server returned an HTTP client error status code (${statusCode}).`
      });
      rawScore -= 10;
    } else if (statusCode && statusCode >= 500) {
      factors.push({
        factor: `Server Error (${statusCode})`,
        impact: -20,
        reason: `Destination server encountered an internal failure (HTTP ${statusCode}).`
      });
      rawScore -= 20;
    }
  } else {
    factors.push({
      factor: 'Connection Unreachable',
      impact: -30,
      reason: 'Target server could not be reached over the public network or DNS lookup failed.'
    });
    rawScore -= 30;
  }

  // 3. Domain Registration (RDAP)
  const rdapAvailable = Boolean(rdap?.available);
  if (rdapAvailable) {
    factors.push({
      factor: 'Authoritative RDAP Record',
      impact: 10,
      reason: 'Authentic registration records confirmed via accredited registry.'
    });
    rawScore += 10;

    // Domain Age Factor
    if (typeof rdap?.ageDays === 'number') {
      const days = rdap.ageDays;
      if (days >= 730) {
        factors.push({
          factor: 'Established Domain Age',
          impact: 15,
          reason: `Domain has an established operational history (${rdap.ageFormatted || `${days} days`}).`
        });
        rawScore += 15;
      } else if (days >= 365) {
        factors.push({
          factor: 'Moderate Domain Age',
          impact: 10,
          reason: `Domain registered over one year ago (${rdap.ageFormatted || `${days} days`}).`
        });
        rawScore += 10;
      } else if (days >= 90) {
        factors.push({
          factor: 'Recent Domain Age',
          impact: 5,
          reason: `Domain registered within the past year (${days} days ago).`
        });
        rawScore += 5;
      } else if (days >= 30) {
        factors.push({
          factor: 'Recently Created Domain',
          impact: -15,
          reason: `Domain was created very recently (${days} days ago). Recently registered domains statistically carry higher risk.`
        });
        rawScore -= 15;
      } else {
        factors.push({
          factor: 'Extremely New Domain',
          impact: -25,
          reason: `Domain registered within the last 30 days (${days} days ago). Exercise elevated caution before sharing credentials or funds.`
        });
        rawScore -= 25;
      }
    }
  } else {
    factors.push({
      factor: 'RDAP Information Unavailable',
      impact: 0,
      reason: 'Authoritative RDAP records were not published by the registry for this TLD (neutral impact).'
    });
  }

  // 4. Redirect Behavior
  if (redirectsCount === 0) {
    factors.push({
      factor: 'Direct Routing',
      impact: 5,
      reason: 'Direct HTTP connection established without intermediary redirect hops.'
    });
    rawScore += 5;
  } else if (redirectsCount === 1) {
    factors.push({
      factor: 'Standard Redirect',
      impact: 0,
      reason: 'Single standard redirect followed (e.g. protocol upgrade or canonical domain routing).'
    });
  } else if (redirectsCount >= 2 && redirectsCount <= 3) {
    factors.push({
      factor: 'Multiple Redirects',
      impact: -5,
      reason: `Request traversed ${redirectsCount} sequential redirect hops.`
    });
    rawScore -= 5;
  } else if (redirectsCount >= 4) {
    factors.push({
      factor: 'Excessive Redirects',
      impact: -15,
      reason: `Request required ${redirectsCount} redirect hops; excessive redirect chains can indicate obfuscation or misconfiguration.`
    });
    rawScore -= 15;
  }

  // 5. Threat Intelligence (VirusTotal)
  const threatIntelAvailable = Boolean(threatIntel?.available);
  if (threatIntelAvailable) {
    const malicious = threatIntel?.malicious || 0;
    const suspicious = threatIntel?.suspicious || 0;
    const total = threatIntel?.totalEngines || 0;

    if (malicious === 0 && suspicious === 0) {
      factors.push({
        factor: 'Clean Threat Intelligence',
        impact: 15,
        reason: `Zero security vendors flagged this domain across ${total} cybersecurity engines.`
      });
      rawScore += 15;
    } else {
      if (suspicious > 0) {
        const penalty = suspicious >= 2 ? -25 : -15;
        factors.push({
          factor: 'Suspicious Telemetry Detections',
          impact: penalty,
          reason: `${suspicious} security engine(s) flagged this domain as suspicious.`
        });
        rawScore += penalty;
      }
      if (malicious > 0) {
        const penalty = malicious >= 2 ? -50 : -35;
        factors.push({
          factor: 'Malicious Threat Detections',
          impact: penalty,
          reason: `${malicious} security vendor(s) reported this domain for malicious or fraudulent activity.`
        });
        rawScore += penalty;
      }
    }
  } else {
    factors.push({
      factor: 'Threat Intelligence Unavailable',
      impact: 0,
      reason: 'External threat telemetry was not configured or unavailable (neutral impact; missing data is not evidence of safety).'
    });
  }

  // Clamp final score between 0 and 100
  const finalScore = Math.max(0, Math.min(100, Math.round(rawScore)));

  // Risk Level Category
  let riskLevel: 'LOW RISK' | 'MEDIUM RISK' | 'HIGH RISK' = 'LOW RISK';
  if (finalScore < 50) {
    riskLevel = 'HIGH RISK';
  } else if (finalScore < 80) {
    riskLevel = 'MEDIUM RISK';
  } else {
    riskLevel = 'LOW RISK';
  }

  // Data availability analysis
  const isLimited = !threatIntelAvailable || !rdapAvailable;
  let notice: string | undefined;
  if (!threatIntelAvailable && !rdapAvailable) {
    notice = 'Analysis is based primarily on live HTTP connectivity. RDAP domain history and threat-intelligence telemetry are currently unavailable.';
  } else if (!threatIntelAvailable) {
    notice = 'Threat-intelligence telemetry is unconfigured on the server. Analysis is based on real HTTP reachability and RDAP domain records.';
  } else if (!rdapAvailable) {
    notice = 'Authoritative RDAP records are unavailable for this domain registry. Analysis is based on HTTP connectivity and threat intelligence.';
  }

  // Dynamic, factual, plain-English explanation
  const explanation = generatePlainEnglishExplanation({
    score: finalScore,
    riskLevel,
    https,
    reachable,
    statusCode,
    rdap,
    threatIntel,
    redirectsCount
  });

  return {
    score: finalScore,
    riskLevel,
    explanation,
    factors,
    dataAvailability: {
      rdapAvailable,
      threatIntelAvailable,
      isLimited,
      notice
    }
  };
}

function generatePlainEnglishExplanation(params: {
  score: number;
  riskLevel: 'LOW RISK' | 'MEDIUM RISK' | 'HIGH RISK';
  https: boolean;
  reachable: boolean;
  statusCode?: number;
  rdap?: RdapResult;
  threatIntel?: ThreatIntelResult;
  redirectsCount: number;
}): string {
  const parts: string[] = [];

  if (!params.reachable) {
    return 'VERISCAN was unable to establish a connection to this website or domain name. An unreachable host cannot be verified for institutional legitimacy or secure data transmission.';
  }

  if (params.riskLevel === 'LOW RISK') {
    parts.push('VERISCAN identified multiple positive trust indicators.');
    if (params.https) {
      parts.push('The website enforces active HTTPS encryption.');
    }
    if (params.rdap?.available && params.rdap.ageFormatted) {
      parts.push(`Domain registration records show an established operational presence (${params.rdap.ageFormatted}).`);
    }
    if (params.threatIntel?.available && params.threatIntel.malicious === 0 && params.threatIntel.suspicious === 0) {
      parts.push('No malicious detections were reported by available threat-intelligence sources.');
    }
    parts.push('These observations suggest low baseline technical risk, but you should always exercise normal consumer discretion before entering personal credentials or financial details.');
  } else if (params.riskLevel === 'MEDIUM RISK') {
    parts.push('VERISCAN observed moderate risk signals or limited available verification data.');
    if (!params.https) {
      parts.push('The website uses unencrypted HTTP, leaving data vulnerable in transit.');
    }
    if (params.rdap?.available && typeof params.rdap.ageDays === 'number' && params.rdap.ageDays < 90) {
      parts.push(`Domain records indicate the domain was created recently (${params.rdap.ageDays} days ago).`);
    }
    if (params.threatIntel?.available && ((params.threatIntel.suspicious || 0) > 0 || (params.threatIntel.malicious || 0) > 0)) {
      parts.push(`Some security engines reported potential detections (${params.threatIntel.malicious || 0} malicious, ${params.threatIntel.suspicious || 0} suspicious).`);
    }
    if (params.redirectsCount >= 3) {
      parts.push(`The URL triggered ${params.redirectsCount} consecutive redirects.`);
    }
    parts.push('Additional verification of the business or organization is recommended before transacting.');
  } else {
    parts.push('VERISCAN identified elevated risk indicators.');
    if (!params.https) {
      parts.push('Transport security is disabled (plain unencrypted HTTP).');
    }
    if (params.threatIntel?.available && (params.threatIntel.malicious || 0) > 0) {
      parts.push(`Multiple security vendors have flagged this domain for malicious or fraudulent activity (${params.threatIntel.malicious} detections).`);
    }
    if (params.rdap?.available && typeof params.rdap.ageDays === 'number' && params.rdap.ageDays < 30) {
      parts.push(`The domain is extremely new (${params.rdap.ageDays} days old).`);
    }
    parts.push('Exercise extreme caution. Do not enter credentials, download software, or make financial payments on this website.');
  }

  return parts.join(' ');
}
