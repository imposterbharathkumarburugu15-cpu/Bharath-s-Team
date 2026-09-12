/**
 * NeuroShield URL Security & SSRF Defense Subsystem
 * Enforces strict RFC 1918 / Cloud Metadata / Loopback protection.
 * Prevents Server-Side Request Forgery (SSRF) and malicious remote execution.
 */

export interface UrlSecurityCheckResult {
  safe: boolean;
  blockedReason?: string;
  normalizedUrl?: string;
  hostname?: string;
  scheme?: string;
  isPrivateOrLoopback?: boolean;
  isCloudMetadata?: boolean;
}

// Comprehensive Private & Loopback IP checks (IPv4 + IPv6)
export function isInternalOrPrivateIP(ip: string): boolean {
  const clean = ip.trim().toLowerCase();

  // IPv4 Loopback (127.0.0.0/8) & 0.0.0.0/8
  if (clean.startsWith('127.') || clean === '127.0.0.1' || clean === '0.0.0.0' || clean.startsWith('0.')) {
    return true;
  }

  // IPv6 Loopback & unspecified
  if (clean === '::1' || clean === '::' || clean === '0:0:0:0:0:0:0:1' || clean === '0:0:0:0:0:0:0:0') {
    return true;
  }

  // RFC 1918 Class A (10.0.0.0/8)
  if (clean.startsWith('10.')) {
    return true;
  }

  // RFC 1918 Class B (172.16.0.0/12)
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(clean)) {
    return true;
  }

  // RFC 1918 Class C (192.168.0.0/16)
  if (clean.startsWith('192.168.')) {
    return true;
  }

  // Link-local / Cloud Metadata (169.254.0.0/16)
  if (clean.startsWith('169.254.')) {
    return true;
  }

  // Carrier Grade NAT (100.64.0.0/10)
  if (/^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./.test(clean)) {
    return true;
  }

  // IPv6 Unique Local (fc00::/7) & Link-local (fe80::/10)
  if (clean.startsWith('fc') || clean.startsWith('fd') || clean.startsWith('fe80:')) {
    return true;
  }

  return false;
}

/**
 * Detects alternate IP encodings used in SSRF bypasses:
 * - Integer / Decimal notation: http://2130706433 (127.0.0.1)
 * - Hex notation: http://0x7f.0.0.1 or http://0x7f000001
 * - Octal notation: http://0177.0.0.1
 */
export function isObfuscatedInternalIP(hostname: string): boolean {
  const h = hostname.trim().toLowerCase();

  // Pure integer / decimal IP (e.g. 2130706433, 2852039166 = 169.254.169.254)
  if (/^\d{8,10}$/.test(h)) {
    const num = parseInt(h, 10);
    if (!isNaN(num) && num >= 0 && num <= 4294967295) {
      const b1 = (num >> 24) & 255;
      const b2 = (num >> 16) & 255;
      const b3 = (num >> 8) & 255;
      const b4 = num & 255;
      const reconstructed = `${b1}.${b2}.${b3}.${b4}`;
      if (isInternalOrPrivateIP(reconstructed)) return true;
    }
  }

  // Hex encoded IP notation (0x7f.0.0.1 or 0x7f000001)
  if (/^0x[0-9a-f]+/i.test(h)) {
    return true; // Block arbitrary hex hostnames as SSRF avoidance
  }

  // Octal encoded parts (e.g. 0177.0.0.1)
  const parts = h.split('.');
  if (parts.length === 4 && parts.some(p => p.length > 1 && p.startsWith('0') && /^[0-7]+$/.test(p))) {
    return true;
  }

  return false;
}

/**
 * Validates a target URL against SSRF and protocol manipulation.
 */
export function validateUrlForSecurity(rawUrl: string): UrlSecurityCheckResult {
  if (!rawUrl || typeof rawUrl !== 'string') {
    return { safe: false, blockedReason: 'URL is empty or not a string' };
  }

  const clean = rawUrl.trim();

  // Reject dangerous non-HTTP schemes
  const lower = clean.toLowerCase();
  if (
    lower.startsWith('file:') ||
    lower.startsWith('gopher:') ||
    lower.startsWith('ftp:') ||
    lower.startsWith('tftp:') ||
    lower.startsWith('ldap:') ||
    lower.startsWith('dict:') ||
    lower.startsWith('javascript:') ||
    lower.startsWith('data:')
  ) {
    return { safe: false, blockedReason: `Unsafe URL scheme detected: ${clean.split(':')[0]}` };
  }

  let parsed: URL;
  try {
    // Add default protocol if missing
    parsed = new URL(clean.includes('://') ? clean : `https://${clean}`);
  } catch (err: any) {
    return { safe: false, blockedReason: `Malformed URL format: ${err?.message || 'Invalid syntax'}` };
  }

  // Validate scheme is strictly http or https
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { safe: false, blockedReason: `Only http and https schemes allowed, got: ${parsed.protocol}` };
  }

  const host = parsed.hostname.toLowerCase();

  // Check known internal hostnames and metadata endpoints
  const BLOCKED_HOSTNAMES = [
    'localhost',
    'localhost.localdomain',
    'ip6-localhost',
    'ip6-loopback',
    'metadata.google.internal',
    '169.254.169.254',
    'instance-data',
    'ecs-local-endpoint'
  ];

  if (BLOCKED_HOSTNAMES.includes(host) || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    return {
      safe: false,
      hostname: host,
      scheme: parsed.protocol,
      isPrivateOrLoopback: true,
      isCloudMetadata: host === '169.254.169.254' || host === 'metadata.google.internal',
      blockedReason: `Access to internal host / metadata endpoint is forbidden (${host})`
    };
  }

  // Check raw IP addresses & alternate encodings
  if (isInternalOrPrivateIP(host) || isObfuscatedInternalIP(host)) {
    return {
      safe: false,
      hostname: host,
      scheme: parsed.protocol,
      isPrivateOrLoopback: true,
      isCloudMetadata: host.startsWith('169.254.'),
      blockedReason: `Private/loopback RFC 1918/link-local address forbidden (${host})`
    };
  }

  return {
    safe: true,
    normalizedUrl: parsed.toString(),
    hostname: host,
    scheme: parsed.protocol,
    isPrivateOrLoopback: false,
    isCloudMetadata: false
  };
}
