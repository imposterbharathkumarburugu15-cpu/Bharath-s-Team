/**
 * Bridge proxy to existing forensic utilities
 */

import {
  parseRawHeaders,
  extractDomainFromEmail,
  checkDomainTyposquatting,
  detectReverseTunnel,
  classifyIP,
  generateSHA256,
  executeEmailForensics,
  ForensicDossier
} from '../forensicsEngine';

export {
  parseRawHeaders,
  extractDomainFromEmail,
  checkDomainTyposquatting,
  detectReverseTunnel,
  classifyIP,
  generateSHA256,
  executeEmailForensics,
};

export type { ForensicDossier };
