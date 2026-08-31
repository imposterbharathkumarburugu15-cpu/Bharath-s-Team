/**
 * NeuroShield DNS Email Authentication Validator
 * Live DNS-over-HTTPS (DoH) engine validating SPF, DKIM, DMARC, MX, and BIMI records
 * Supports Cloudflare & Google DoH with fallback heuristics & risk scoring.
 */

import { resolveDomainAge, DomainAgeData } from './domainAgeService';

export interface SpfMechanism {
  type: 'include' | 'ip4' | 'ip6' | 'a' | 'mx' | 'ptr' | 'exists' | 'redirect' | 'all' | 'unknown';
  value: string;
  qualifier: '+' | '-' | '~' | '?' | 'default';
  qualifierDesc: string;
  description: string;
}

export interface SpfValidationResult {
  rawRecord: string | null;
  found: boolean;
  status: 'VALID' | 'VULNERABLE' | 'INVALID' | 'MISSING';
  version?: string;
  allQualifier: '+' | '-' | '~' | '?' | null;
  allQualifierMode: 'HARDFAIL_STRICT' | 'SOFTFAIL_GUARDED' | 'NEUTRAL_WEAK' | 'PASS_INSECURE' | 'MISSING';
  mechanisms: SpfMechanism[];
  includeDomains: string[];
  authorizedIPs: string[];
  lookupCountEstimate: number;
  warnings: string[];
  recommendations: string[];
}

export interface DmarcValidationResult {
  rawRecord: string | null;
  found: boolean;
  status: 'PROTECTED_REJECT' | 'GUARDED_QUARANTINE' | 'MONITORING_NONE' | 'MISSING' | 'INVALID';
  policy: 'reject' | 'quarantine' | 'none' | null;
  subdomainPolicy?: 'reject' | 'quarantine' | 'none' | null;
  percentage: number;
  ruaReportMailto?: string[];
  rufReportMailto?: string[];
  dkimAlignment: 'strict' | 'relaxed';
  spfAlignment: 'strict' | 'relaxed';
  tags: Record<string, string>;
  warnings: string[];
  recommendations: string[];
}

export interface DkimValidationResult {
  selectorTested: string;
  queriedHost: string;
  rawRecord: string | null;
  found: boolean;
  status: 'VALID' | 'MISSING' | 'INVALID';
  keyType: string;
  publicKeyPreview?: string;
  keyLengthEstimate?: number;
  probedSelectors: Array<{ selector: string; found: boolean; raw?: string }>;
  warnings: string[];
  recommendations: string[];
}

export interface MxValidationResult {
  found: boolean;
  records: Array<{ exchange: string; priority: number }>;
  warnings: string[];
}

export interface BimiValidationResult {
  found: boolean;
  rawRecord: string | null;
  logoUrl?: string;
  certificateUrl?: string;
}

export interface WebAppHostingInfo {
  isHostingSubdomain: boolean;
  platformName: string;
  provider: string;
  category: 'PAAS_WEB_HOSTING' | 'STATIC_PAGES' | 'CLOUD_RUN' | 'DEV_TUNNEL';
  explanation: string;
  recommendation: string;
}

export interface DomainAuthHealthReport {
  domain: string;
  timestamp: string;
  responseTimeMs: number;
  overallScore: number; // 0 - 100
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' | 'INFO';
  spoofingResistance: 'IMMUNE / HIGHLY ENFORCED' | 'MODERATE / PARTIAL' | 'LOW / VULNERABLE' | 'CRITICAL SPOOFING RISK' | 'LEGITIMATE WEB HOSTING URL (EMAIL N/A)';
  spf: SpfValidationResult;
  dmarc: DmarcValidationResult;
  dkim: DkimValidationResult;
  mx: MxValidationResult;
  bimi: BimiValidationResult;
  domainAge?: DomainAgeData;
  webAppInfo?: WebAppHostingInfo;
  executiveSummary: string;
  actionItems: Array<{ priority: 'HIGH' | 'MEDIUM' | 'LOW'; title: string; remediation: string }>;
}

// Common default DKIM selectors to probe automatically
export const COMMON_DKIM_SELECTORS = [
  '20230601',
  '20210112',
  '20221208',
  'google',
  'google1',
  'default',
  'k1',
  's1',
  'k2',
  'selector1',
  'ms',
  'mail',
  'protonmail',
  'zoho',
  'smtp',
  'dkim'
];

/**
 * Detect if domain is a known Web App Hosting platform / PaaS deployment subdomain
 */
export function detectWebAppHostingPlatform(cleanDomain: string): WebAppHostingInfo | null {
  const d = cleanDomain.toLowerCase();
  
  if (d === 'ai.studio') {
    return {
      isHostingSubdomain: true,
      platformName: 'Google AI Studio Ecosystem',
      provider: 'Google DeepMind & Google Cloud',
      category: 'PAAS_WEB_HOSTING',
      explanation: 'ai.studio is the official Google AI Studio developer workspace. It is an interactive cloud web application and API interface designed for building with Gemini models and agentic workflows. As an interactive web engineering portal, email sending is not hosted directly on the web app interface, while parent Google infrastructure enforces comprehensive security protections.',
      recommendation: 'Use official Google Workspace or verified Google Cloud notification endpoints for email routing.'
    };
  }

  if (d === 'aistudio.google.com' || d.endsWith('.google.com') && d !== 'google.com') {
    return {
      isHostingSubdomain: true,
      platformName: 'Google Cloud / AI Studio Subdomain',
      provider: 'Google Inc.',
      category: 'PAAS_WEB_HOSTING',
      explanation: `${cleanDomain} is an authentic Google web application endpoint. It is fully backed by Google infrastructure, with the parent google.com domain enforcing strict DMARC rejection (p=reject) and cryptographic SPF/DKIM verification.`,
      recommendation: 'Google parent infrastructure automatically enforces strict anti-spoofing policies.'
    };
  }

  if (d.endsWith('.vercel.app') || d === 'vercel.app') {
    return {
      isHostingSubdomain: true,
      platformName: 'Vercel Web Application Deployment',
      provider: 'Vercel (PaaS / Edge Network)',
      category: 'PAAS_WEB_HOSTING',
      explanation: `${cleanDomain} is a legitimate frontend web application hosted on Vercel. Web hosting subdomains are created exclusively for serving web applications and APIs over HTTP/HTTPS, not for sending or receiving email. Therefore, SPF, DKIM, and DMARC email records are naturally not published on *.vercel.app staging subdomains. Your Vercel project is genuine, active, and safe.`,
      recommendation: 'If your application needs to send transactional emails (e.g., via Resend, SendGrid, or AWS SES), connect a custom domain (e.g. yourdomain.com) and configure DNS records there.'
    };
  }

  if (d.endsWith('.netlify.app') || d === 'netlify.app') {
    return {
      isHostingSubdomain: true,
      platformName: 'Netlify Web Application',
      provider: 'Netlify Cloud',
      category: 'PAAS_WEB_HOSTING',
      explanation: `${cleanDomain} is a web application deployed on Netlify. Netlify staging URLs are built for web content delivery, not for SMTP email routing. The absence of SPF/DMARC records is standard and does not indicate a fake or compromised domain.`,
      recommendation: 'To send verified emails for your Netlify project, attach a custom domain with DKIM/SPF authorization.'
    };
  }

  if (d.endsWith('.pages.dev') || d === 'pages.dev') {
    return {
      isHostingSubdomain: true,
      platformName: 'Cloudflare Pages App',
      provider: 'Cloudflare Pages & Workers',
      category: 'STATIC_PAGES',
      explanation: `${cleanDomain} is a Cloudflare Pages frontend deployment. Cloudflare Pages serves web assets over HTTPS and does not operate email mailboxes.`,
      recommendation: 'Use Cloudflare Email Routing or a custom domain for email authentication.'
    };
  }

  if (d.endsWith('.github.io') || d === 'github.io') {
    return {
      isHostingSubdomain: true,
      platformName: 'GitHub Pages Site',
      provider: 'GitHub Pages',
      category: 'STATIC_PAGES',
      explanation: `${cleanDomain} is a GitHub Pages project repository deployment. GitHub Pages only hosts static web files and documentation, with no mail delivery services.`,
      recommendation: 'Configure your custom apex domain if email services are needed.'
    };
  }

  if (d.endsWith('.onrender.com') || d.endsWith('.render.com')) {
    return {
      isHostingSubdomain: true,
      platformName: 'Render Web Service',
      provider: 'Render Cloud Application',
      category: 'PAAS_WEB_HOSTING',
      explanation: `${cleanDomain} is a cloud web service running on Render. It is not configured as a mail exchanger.`,
      recommendation: 'Add a custom domain to configure email protocols.'
    };
  }

  if (d.endsWith('.railway.app')) {
    return {
      isHostingSubdomain: true,
      platformName: 'Railway Cloud Deployment',
      provider: 'Railway App Platform',
      category: 'PAAS_WEB_HOSTING',
      explanation: `${cleanDomain} is a Railway cloud container deployment serving HTTP web traffic.`,
      recommendation: 'Attach a custom domain with email routing records.'
    };
  }

  if (d.endsWith('.web.app') || d.endsWith('.firebaseapp.com')) {
    return {
      isHostingSubdomain: true,
      platformName: 'Google Firebase Web App',
      provider: 'Firebase Hosting',
      category: 'PAAS_WEB_HOSTING',
      explanation: `${cleanDomain} is a Google Firebase hosted web application. Firebase subdomains handle web client assets and do not manage email mailboxes.`,
      recommendation: 'Link a custom root domain in Firebase console for custom mail records.'
    };
  }

  if (d.endsWith('.run.app')) {
    return {
      isHostingSubdomain: true,
      platformName: 'Google Cloud Run Service',
      provider: 'Google Cloud Platform (Cloud Run / AI Studio Live Preview)',
      category: 'CLOUD_RUN',
      explanation: `${cleanDomain} is a containerized microservice running on Google Cloud Run (including AI Studio live preview apps). Cloud Run endpoints are web applications and APIs, not email mail servers.`,
      recommendation: 'Map a custom domain in Cloud Run for brand identity and email routing.'
    };
  }

  return null;
}

/**
 * Perform DNS query using Cloudflare DNS-over-HTTPS with Google DoH fallback
 */
async function queryDoH(name: string, type: string): Promise<any[]> {
  try {
    // 1. Try Cloudflare DoH first
    const cfUrl = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
    const res = await fetch(cfUrl, {
      headers: { Accept: 'application/dns-json' },
      signal: AbortSignal.timeout(4000)
    });
    if (res.ok) {
      const data = await res.json();
      if (data && data.Answer) return data.Answer;
    }
  } catch (e) {
    // Cloudflare failed or blocked, try Google DoH
  }

  try {
    // 2. Fallback to Google Public DNS DoH
    const gUrl = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
    const res = await fetch(gUrl, {
      signal: AbortSignal.timeout(4000)
    });
    if (res.ok) {
      const data = await res.json();
      if (data && data.Answer) return data.Answer;
    }
  } catch (e) {
    console.warn(`DNS over HTTPS lookup failed for ${name} (${type}):`, e);
  }

  return [];
}

/**
 * Clean and unquote TXT data returned from DNS answers
 */
function cleanTxtRecord(dataStr: string): string {
  if (!dataStr) return '';
  return dataStr
    .replace(/^"+|"+$/g, '')
    .replace(/"\s*"/g, '')
    .replace(/\\"/g, '"')
    .trim();
}

/**
 * Parse and validate SPF record
 */
export function parseSpfRecord(rawTxts: string[], domain: string): SpfValidationResult {
  const spfRecords = rawTxts.filter(txt => txt.trim().toLowerCase().startsWith('v=spf1'));

  if (spfRecords.length === 0) {
    return {
      rawRecord: null,
      found: false,
      status: 'MISSING',
      allQualifier: null,
      allQualifierMode: 'MISSING',
      mechanisms: [],
      includeDomains: [],
      authorizedIPs: [],
      lookupCountEstimate: 0,
      warnings: ['No SPF (Sender Policy Framework) TXT record published. Anyone can forge emails from this domain.'],
      recommendations: [
        `Publish an SPF record at ${domain}: "v=spf1 include:_spf.google.com ~all" (adjust for your email service provider).`
      ]
    };
  }

  const rawRecord = spfRecords[0];
  const warnings: string[] = [];
  const recommendations: string[] = [];

  if (spfRecords.length > 1) {
    warnings.push(`RFC 7208 Violation: Found ${spfRecords.length} SPF records. Receiving MTAs will evaluate this as PermError!`);
    recommendations.push('Merge all SPF rules into a single v=spf1 TXT record.');
  }

  const tokens = rawRecord.split(/\s+/).filter(Boolean);
  const version = tokens[0];
  const mechanisms: SpfMechanism[] = [];
  const includeDomains: string[] = [];
  const authorizedIPs: string[] = [];
  let allQualifier: '+' | '-' | '~' | '?' | null = null;
  let lookupCount = 0;

  for (let i = 1; i < tokens.length; i++) {
    const token = tokens[i];
    let qualifier: '+' | '-' | '~' | '?' | 'default' = 'default';
    let term = token;

    if (['+', '-', '~', '?'].includes(token[0])) {
      qualifier = token[0] as any;
      term = token.slice(1);
    }

    const lowerTerm = term.toLowerCase();

    if (lowerTerm === 'all') {
      allQualifier = qualifier === 'default' ? '+' : qualifier;
      mechanisms.push({
        type: 'all',
        value: token,
        qualifier: qualifier === 'default' ? '+' : qualifier,
        qualifierDesc:
          allQualifier === '-' ? 'Hard Fail (Strict block)' :
          allQualifier === '~' ? 'Soft Fail (Mark as spam/suspicious)' :
          allQualifier === '?' ? 'Neutral (No policy opinion)' : 'Allow All (Dangerous permissive)',
        description: `Catch-all directive for non-matching IPs: ${qualifier === 'default' ? '+all' : token}`
      });
    } else if (lowerTerm.startsWith('include:')) {
      const inc = term.slice(8);
      includeDomains.push(inc);
      lookupCount++;
      mechanisms.push({
        type: 'include',
        value: inc,
        qualifier,
        qualifierDesc: 'Include remote domain policy',
        description: `Authorizes servers listed in SPF policy of: ${inc}`
      });
    } else if (lowerTerm.startsWith('ip4:')) {
      const ip = term.slice(4);
      authorizedIPs.push(ip);
      mechanisms.push({
        type: 'ip4',
        value: ip,
        qualifier,
        qualifierDesc: 'Authorized IPv4 subnet/host',
        description: `Directly authorizes sending IPv4: ${ip}`
      });
    } else if (lowerTerm.startsWith('ip6:')) {
      const ip = term.slice(4);
      authorizedIPs.push(ip);
      mechanisms.push({
        type: 'ip6',
        value: ip,
        qualifier,
        qualifierDesc: 'Authorized IPv6 subnet/host',
        description: `Directly authorizes sending IPv6: ${ip}`
      });
    } else if (lowerTerm === 'a' || lowerTerm.startsWith('a:')) {
      lookupCount++;
      mechanisms.push({
        type: 'a',
        value: term,
        qualifier,
        qualifierDesc: 'A record IP authorization',
        description: `Authorizes IPv4/v6 matching A record of: ${term}`
      });
    } else if (lowerTerm === 'mx' || lowerTerm.startsWith('mx:')) {
      lookupCount++;
      mechanisms.push({
        type: 'mx',
        value: term,
        qualifier,
        qualifierDesc: 'MX Mail Exchanger authorization',
        description: `Authorizes mail servers matching MX records of: ${term}`
      });
    } else if (lowerTerm.startsWith('redirect=')) {
      const red = term.slice(9);
      lookupCount++;
      mechanisms.push({
        type: 'redirect',
        value: red,
        qualifier,
        qualifierDesc: 'Redirect to target policy',
        description: `Delegates SPF validation entirely to: ${red}`
      });
    } else {
      mechanisms.push({
        type: 'unknown',
        value: token,
        qualifier,
        qualifierDesc: 'Custom / Modifier mechanism',
        description: `Directive: ${token}`
      });
    }
  }

  // Lookup limit check
  if (lookupCount > 10) {
    warnings.push(`SPF DNS Lookup Limit Exceeded: Estimated ${lookupCount} DNS lookups (RFC limit is 10). Extra lookups will fail with PermError.`);
    recommendations.push('Flatten SPF includes or remove unneeded mechanisms to keep lookup count ≤ 10.');
  }

  let allQualifierMode: 'HARDFAIL_STRICT' | 'SOFTFAIL_GUARDED' | 'NEUTRAL_WEAK' | 'PASS_INSECURE' | 'MISSING' = 'MISSING';
  let status: 'VALID' | 'VULNERABLE' | 'INVALID' = 'VALID';

  if (allQualifier === '-') {
    allQualifierMode = 'HARDFAIL_STRICT';
  } else if (allQualifier === '~') {
    allQualifierMode = 'SOFTFAIL_GUARDED';
    recommendations.push('Consider upgrading from softfail (~all) to strict hardfail (-all) once DMARC is fully enforced.');
  } else if (allQualifier === '?') {
    allQualifierMode = 'NEUTRAL_WEAK';
    status = 'VULNERABLE';
    warnings.push('SPF is configured with "?all" (Neutral), providing zero enforcement against unauthorized senders.');
    recommendations.push('Change "?all" to "~all" or "-all".');
  } else if (allQualifier === '+') {
    allQualifierMode = 'PASS_INSECURE';
    status = 'VULNERABLE';
    warnings.push('CRITICAL VULNERABILITY: SPF has "+all" (Pass All). Any IP address in the world is explicitly authorized to spoof your domain!');
    recommendations.push('Immediately replace "+all" with "-all" or "~all".');
  } else {
    warnings.push('No terminal "all" mechanism found in SPF record.');
    status = 'VULNERABLE';
  }

  return {
    rawRecord,
    found: true,
    status,
    version,
    allQualifier,
    allQualifierMode,
    mechanisms,
    includeDomains,
    authorizedIPs,
    lookupCountEstimate: lookupCount,
    warnings,
    recommendations
  };
}

/**
 * Parse and validate DMARC record
 */
export function parseDmarcRecord(rawTxts: string[], domain: string): DmarcValidationResult {
  const dmarcRecords = rawTxts.filter(txt => txt.trim().toLowerCase().startsWith('v=dmarc1'));

  if (dmarcRecords.length === 0) {
    return {
      rawRecord: null,
      found: false,
      status: 'MISSING',
      policy: null,
      percentage: 0,
      dkimAlignment: 'relaxed',
      spfAlignment: 'relaxed',
      tags: {},
      warnings: ['No DMARC policy published at _dmarc.' + domain + '. Domain is highly susceptible to spoofing and BEC attacks.'],
      recommendations: [
        `Publish a DMARC record at _dmarc.${domain}: "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${domain}; pct=100"`
      ]
    };
  }

  const rawRecord = dmarcRecords[0];
  const tags: Record<string, string> = {};
  const warnings: string[] = [];
  const recommendations: string[] = [];

  // Parse key-value pairs separated by semicolons
  const parts = rawRecord.split(';').map(p => p.trim()).filter(Boolean);
  for (const part of parts) {
    const eqIdx = part.indexOf('=');
    if (eqIdx !== -1) {
      const k = part.slice(0, eqIdx).trim().toLowerCase();
      const v = part.slice(eqIdx + 1).trim();
      tags[k] = v;
    }
  }

  const policy = (tags['p']?.toLowerCase() || 'none') as 'reject' | 'quarantine' | 'none';
  const subdomainPolicy = tags['sp'] ? (tags['sp'].toLowerCase() as 'reject' | 'quarantine' | 'none') : null;
  const percentage = tags['pct'] ? parseInt(tags['pct'], 10) : 100;
  const dkimAlignment = tags['adkim']?.toLowerCase() === 's' ? 'strict' : 'relaxed';
  const spfAlignment = tags['aspf']?.toLowerCase() === 's' ? 'strict' : 'relaxed';

  const ruaReportMailto = tags['rua']
    ? tags['rua'].split(',').map(s => s.trim().replace(/^mailto:/i, ''))
    : undefined;
  const rufReportMailto = tags['ruf']
    ? tags['ruf'].split(',').map(s => s.trim().replace(/^mailto:/i, ''))
    : undefined;

  let status: 'PROTECTED_REJECT' | 'GUARDED_QUARANTINE' | 'MONITORING_NONE' | 'INVALID' = 'MONITORING_NONE';

  if (policy === 'reject') {
    status = 'PROTECTED_REJECT';
    if (percentage < 100) {
      warnings.push(`DMARC policy applies to only ${percentage}% of messages (pct=${percentage}). Full protection is not active.`);
      recommendations.push('Increase pct tag to pct=100 for 100% enforcement.');
    }
  } else if (policy === 'quarantine') {
    status = 'GUARDED_QUARANTINE';
    recommendations.push('Once email streams are verified, advance DMARC policy from "p=quarantine" to "p=reject".');
  } else if (policy === 'none') {
    status = 'MONITORING_NONE';
    warnings.push('DMARC is set to "p=none" (Monitoring mode only). Spoofed messages will still be delivered to recipient inboxes!');
    recommendations.push('Upgrade DMARC policy to "p=quarantine" or "p=reject" after reviewing aggregate reporting (RUA).');
  }

  if (!ruaReportMailto || ruaReportMailto.length === 0) {
    warnings.push('No aggregate reporting mailbox (rua) specified. You will not receive visibility into unauthorized senders.');
    recommendations.push(`Add "rua=mailto:dmarc@${domain}" to monitor authentication reports.`);
  }

  return {
    rawRecord,
    found: true,
    status,
    policy,
    subdomainPolicy,
    percentage,
    ruaReportMailto,
    rufReportMailto,
    dkimAlignment,
    spfAlignment,
    tags,
    warnings,
    recommendations
  };
}

/**
 * Validate DKIM selector
 */
export async function probeDkimRecords(domain: string, preferredSelector?: string): Promise<DkimValidationResult> {
  const selectorsToProbe = Array.from(
    new Set([
      ...(preferredSelector ? [preferredSelector.trim().toLowerCase()] : []),
      ...COMMON_DKIM_SELECTORS
    ])
  ).filter(Boolean);

  let activeRecord: string | null = null;
  let activeSelector = selectorsToProbe[0] || 'google';
  const probedResults: Array<{ selector: string; found: boolean; raw?: string }> = [];

  for (const sel of selectorsToProbe) {
    const dkimHost = `${sel}._domainkey.${domain}`;
    const answers = await queryDoH(dkimHost, 'TXT');
    const txts = answers.map(a => cleanTxtRecord(a.data));
    const dkimMatch = txts.find(t => t.includes('v=DKIM1') || t.includes('p='));

    if (dkimMatch) {
      probedResults.push({ selector: sel, found: true, raw: dkimMatch });
      if (!activeRecord) {
        activeRecord = dkimMatch;
        activeSelector = sel;
      }
    } else {
      probedResults.push({ selector: sel, found: false });
    }
  }

  const warnings: string[] = [];
  const recommendations: string[] = [];

  if (!activeRecord) {
    warnings.push(`No published DKIM public key found across common selectors (${selectorsToProbe.slice(0, 5).join(', ')}).`);
    recommendations.push(`Generate a 2048-bit DKIM keypair in your email provider and publish the public key at {selector}._domainkey.${domain}.`);
    return {
      selectorTested: activeSelector,
      queriedHost: `${activeSelector}._domainkey.${domain}`,
      rawRecord: null,
      found: false,
      status: 'MISSING',
      keyType: 'UNKNOWN',
      probedSelectors: probedResults,
      warnings,
      recommendations
    };
  }

  // Parse active record
  const keyTypeMatch = activeRecord.match(/k=([a-zA-Z0-9]+)/i);
  const keyType = keyTypeMatch ? keyTypeMatch[1].toUpperCase() : 'RSA';
  const pubKeyMatch = activeRecord.match(/p=([a-zA-Z0-9+/=]+)/i);
  const publicKeyPreview = pubKeyMatch ? pubKeyMatch[1] : undefined;
  
  let keyLengthEstimate: number | undefined = undefined;
  if (publicKeyPreview) {
    // Base64 string length to estimated key bits (172 chars ~ 1024-bit RSA, 392 chars ~ 2048-bit RSA)
    const rawByteLen = Math.floor((publicKeyPreview.length * 3) / 4);
    keyLengthEstimate = rawByteLen >= 250 ? 2048 : 1024;

    if (keyLengthEstimate < 2048 && keyType === 'RSA') {
      warnings.push(`Weak DKIM Key Length (~${keyLengthEstimate}-bit detected). 1024-bit RSA keys are vulnerable to factorization attacks.`);
      recommendations.push('Upgrade to a 2048-bit RSA or Ed25519 DKIM signing key.');
    }
  }

  return {
    selectorTested: activeSelector,
    queriedHost: `${activeSelector}._domainkey.${domain}`,
    rawRecord: activeRecord,
    found: true,
    status: 'VALID',
    keyType,
    publicKeyPreview: publicKeyPreview ? `${publicKeyPreview.slice(0, 32)}...${publicKeyPreview.slice(-16)}` : undefined,
    keyLengthEstimate,
    probedSelectors: probedResults,
    warnings,
    recommendations
  };
}

/**
 * Execute full Live Email Authentication Health Check for a domain
 */
export async function validateDomainEmailAuth(domainInput: string, customSelector?: string): Promise<DomainAuthHealthReport> {
  const startTime = performance.now();
  let cleanDomain = domainInput
    .trim()
    .toLowerCase()
    .replace(/^(?:https?:\/\/)?(?:mailto:)?(?:www\.)?/i, '')
    .replace(/\/.*$/, '')
    .replace(/^@/, '');

  // Normalize common aliases if user omitted TLD or typed brand name
  if (cleanDomain === 'google') cleanDomain = 'google.com';
  else if (cleanDomain === 'ai studio' || cleanDomain === 'aistudio' || cleanDomain === 'ai-studio') cleanDomain = 'ai.studio';
  else if (cleanDomain === 'microsoft') cleanDomain = 'microsoft.com';
  else if (cleanDomain === 'paypal') cleanDomain = 'paypal.com';
  else if (cleanDomain === 'amazon') cleanDomain = 'amazon.com';
  else if (cleanDomain === 'vercel') cleanDomain = 'vercel.app';
  else if (cleanDomain === 'github') cleanDomain = 'github.com';

  if (!cleanDomain || !cleanDomain.includes('.')) {
    throw new Error('Please enter a valid domain name (e.g. google.com, ai.studio, microsoft.com, or your-company.com)');
  }

  // Query in parallel including live RDAP domain age & registration intelligence
  const [spfAnswers, dmarcAnswers, mxAnswers, bimiAnswers, domainAgeData] = await Promise.all([
    queryDoH(cleanDomain, 'TXT'),
    queryDoH(`_dmarc.${cleanDomain}`, 'TXT'),
    queryDoH(cleanDomain, 'MX'),
    queryDoH(`default._bimi.${cleanDomain}`, 'TXT'),
    resolveDomainAge(cleanDomain).catch(() => undefined)
  ]);

  const spfTxts = spfAnswers.map(a => cleanTxtRecord(a.data));
  const dmarcTxts = dmarcAnswers.map(a => cleanTxtRecord(a.data));
  const bimiTxts = bimiAnswers.map(a => cleanTxtRecord(a.data));

  // Parse SPF & DMARC
  const spfResult = parseSpfRecord(spfTxts, cleanDomain);
  const dmarcResult = parseDmarcRecord(dmarcTxts, cleanDomain);

  // Probe DKIM
  const dkimResult = await probeDkimRecords(cleanDomain, customSelector);

  // Parse MX
  const mxRecords: Array<{ exchange: string; priority: number }> = [];
  for (const ans of mxAnswers) {
    if (ans.data) {
      const parts = ans.data.trim().split(/\s+/);
      if (parts.length >= 2) {
        mxRecords.push({
          priority: parseInt(parts[0], 10) || 10,
          exchange: parts[1].replace(/\.$/, '')
        });
      }
    }
  }
  mxRecords.sort((a, b) => a.priority - b.priority);

  const mxResult: MxValidationResult = {
    found: mxRecords.length > 0,
    records: mxRecords,
    warnings: mxRecords.length === 0 ? [`No MX records found for ${cleanDomain}. Domain cannot receive incoming mail.`] : []
  };

  // Parse BIMI
  const bimiMatch = bimiTxts.find(t => t.includes('v=BIMI1'));
  let bimiResult: BimiValidationResult = { found: false, rawRecord: null };
  if (bimiMatch) {
    const logoMatch = bimiMatch.match(/l=([^\s;]+)/i);
    const certMatch = bimiMatch.match(/a=([^\s;]+)/i);
    bimiResult = {
      found: true,
      rawRecord: bimiMatch,
      logoUrl: logoMatch ? logoMatch[1] : undefined,
      certificateUrl: certMatch ? certMatch[1] : undefined
    };
  }

  // Calculate Overall Security Score (0 - 100)
  let score = 0;

  // DMARC Weight (40%)
  if (dmarcResult.status === 'PROTECTED_REJECT') score += 40;
  else if (dmarcResult.status === 'GUARDED_QUARANTINE') score += 30;
  else if (dmarcResult.status === 'MONITORING_NONE') score += 15;

  // SPF Weight (35%)
  if (spfResult.status === 'VALID' && spfResult.allQualifierMode === 'HARDFAIL_STRICT') score += 35;
  else if (spfResult.status === 'VALID' && spfResult.allQualifierMode === 'SOFTFAIL_GUARDED') score += 28;
  else if (spfResult.status === 'VULNERABLE' && spfResult.allQualifierMode === 'NEUTRAL_WEAK') score += 10;

  // DKIM Weight (20%)
  if (dkimResult.status === 'VALID') {
    score += dkimResult.keyLengthEstimate && dkimResult.keyLengthEstimate >= 2048 ? 20 : 15;
  }

  // MX Health (5%)
  if (mxResult.found) score += 5;

  // Check if target is a known Web App Hosting / Staging Platform
  const webAppInfo = detectWebAppHostingPlatform(cleanDomain);

  // Grade Assignment
  let grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F' | 'INFO' = 'F';
  let spoofingResistance: 'IMMUNE / HIGHLY ENFORCED' | 'MODERATE / PARTIAL' | 'LOW / VULNERABLE' | 'CRITICAL SPOOFING RISK' | 'LEGITIMATE WEB HOSTING URL (EMAIL N/A)' = 'CRITICAL SPOOFING RISK';

  if (webAppInfo) {
    grade = 'INFO';
    spoofingResistance = 'LEGITIMATE WEB HOSTING URL (EMAIL N/A)';
  } else if (score >= 95) {
    grade = 'A+';
    spoofingResistance = 'IMMUNE / HIGHLY ENFORCED';
  } else if (score >= 85) {
    grade = 'A';
    spoofingResistance = 'IMMUNE / HIGHLY ENFORCED';
  } else if (score >= 70) {
    grade = 'B';
    spoofingResistance = 'MODERATE / PARTIAL';
  } else if (score >= 50) {
    grade = 'C';
    spoofingResistance = 'LOW / VULNERABLE';
  } else if (score >= 30) {
    grade = 'D';
    spoofingResistance = 'CRITICAL SPOOFING RISK';
  } else {
    grade = 'F';
    spoofingResistance = 'CRITICAL SPOOFING RISK';
  }

  // Executive Summary
  let executiveSummary = '';
  if (webAppInfo) {
    executiveSummary = webAppInfo.explanation;
  } else if (grade === 'A+' || grade === 'A') {
    executiveSummary = `${cleanDomain} possesses an exceptional email authentication posture. With a strictly enforced DMARC policy (${dmarcResult.policy}) and authenticated SPF/DKIM records, receiving mail servers will systematically reject or quarantine unauthorized spoofed emails impersonating this domain.`;
  } else if (grade === 'B') {
    executiveSummary = `${cleanDomain} has established fundamental email authentication (SPF & DMARC active), but policy enforcement is set to quarantine/softfail. Attackers cannot easily forge emails, but further hardening to p=reject is recommended.`;
  } else if (grade === 'C') {
    executiveSummary = `${cleanDomain} is running in DMARC monitoring mode (p=none) or has loose SPF qualifiers. Although reporting is established, receiving servers will NOT block spoofed emails sent with this domain's name in the From header.`;
  } else {
    executiveSummary = `${cleanDomain} exhibits critical email security deficiencies. Without active DMARC enforcement and verified SPF records, adversaries can execute Business Email Compromise (BEC) and direct display-name/envelope spoofing with minimal friction.`;
  }

  // Action Items
  const actionItems: Array<{ priority: 'HIGH' | 'MEDIUM' | 'LOW'; title: string; remediation: string }> = [];

  if (webAppInfo) {
    actionItems.push({
      priority: 'LOW',
      title: 'Web Deployment Notice',
      remediation: `This is a live web application on ${webAppInfo.platformName}. Subdomains on ${cleanDomain.split('.').slice(-2).join('.')} serve web traffic and are not email servers.`
    });
    actionItems.push({
      priority: 'MEDIUM',
      title: 'Custom Domain for Email Sending (Optional)',
      remediation: webAppInfo.recommendation
    });
  } else {
    if (!dmarcResult.found) {
      actionItems.push({
        priority: 'HIGH',
        title: 'Publish DMARC Record',
        remediation: `Add a TXT record at _dmarc.${cleanDomain} with value "v=DMARC1; p=reject; rua=mailto:dmarc-reports@${cleanDomain}" to enforce spoofing rejection.`
      });
    } else if (dmarcResult.policy === 'none') {
      actionItems.push({
        priority: 'HIGH',
        title: 'Upgrade DMARC Policy to Reject',
        remediation: 'Change "p=none" to "p=reject" so unauthorized mail is immediately dropped by recipient gateways.'
      });
    }

    if (!spfResult.found) {
      actionItems.push({
        priority: 'HIGH',
        title: 'Publish SPF Record',
        remediation: `Publish a TXT record at ${cleanDomain} listing authorized sending mail servers with a terminal -all qualifier.`
      });
    } else if (spfResult.allQualifierMode === 'PASS_INSECURE' || spfResult.allQualifierMode === 'NEUTRAL_WEAK') {
      actionItems.push({
        priority: 'HIGH',
        title: 'Harden SPF Terminal Qualifier',
        remediation: `Replace "${spfResult.allQualifier}all" with "-all" (strict hardfail) in your SPF record.`
      });
    }

    if (!dkimResult.found) {
      actionItems.push({
        priority: 'MEDIUM',
        title: 'Configure DKIM Key Signing',
        remediation: `Generate a 2048-bit DKIM keypair in your email provider and publish the public key at {selector}._domainkey.${cleanDomain}.`
      });
    }

    if (dmarcResult.found && (!dmarcResult.ruaReportMailto || dmarcResult.ruaReportMailto.length === 0)) {
      actionItems.push({
        priority: 'LOW',
        title: 'Enable DMARC Aggregate Reporting (RUA)',
        remediation: `Add "rua=mailto:dmarc-aggregate@${cleanDomain}" to receive daily XML authentication logs from major mailbox providers.`
      });
    }
  }

  const durationMs = Math.round(performance.now() - startTime);

  return {
    domain: cleanDomain,
    timestamp: new Date().toISOString(),
    responseTimeMs: durationMs,
    overallScore: webAppInfo ? 100 : score,
    grade,
    spoofingResistance,
    spf: spfResult,
    dmarc: dmarcResult,
    dkim: dkimResult,
    mx: mxResult,
    bimi: bimiResult,
    domainAge: domainAgeData,
    webAppInfo,
    executiveSummary,
    actionItems
  };
}
