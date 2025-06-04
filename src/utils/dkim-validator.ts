import { resolveTxt } from './dns-resolver';
import { DKIMValidationResult } from '../types/dkim';


function isValidDomain(domain: string): boolean {
  if (!domain || typeof domain !== 'string') return false;
  if (domain.length > 253 || !domain.includes('.')) return false;
  const labelRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
  return domain.split('.').every(label => label.length > 0 && label.length <= 63 && labelRegex.test(label));
}

function isValidSelector(selector: string): boolean {
  return !!selector && /^[a-zA-Z0-9_-]{1,63}$/.test(selector);
}

export async function validateDKIM(selector: string, domain: string): Promise<DKIMValidationResult> {
  if (!isValidSelector(selector)) {
    return { selector, domain, valid: false, error: 'Invalid DKIM selector' };
  }
  if (!isValidDomain(domain)) {
    return { selector, domain, valid: false, error: 'Invalid domain' };
  }
  const dkimHostname = `${selector}._domainkey.${domain}`;
  try {
    const txtRecords = await resolveTxt(dkimHostname);
    const flatRecords = txtRecords.map(r => r.join('')).join('\n');
    const match = flatRecords.match(/v=DKIM1\s*;[^\n]+/i);
    if (!match) {
      return { selector, domain, valid: false, error: 'No DKIM record found' };
    }
    return { selector, domain, valid: true, record: match[0] };
  } catch (error: any) {
    // Handle NXDOMAIN (status 3) as a warning, not an error, and do not print stack trace
    if (typeof error?.message === 'string' && error.message.includes('status 3')) {
      console.warn(`[DKIM] Warning: No DKIM record for selector '${selector}' on domain '${domain}' (NXDOMAIN)`);
      return { selector, domain, valid: false, error: 'No DKIM record found (NXDOMAIN)' };
    } else {
      // Other errors: log as warning, no stack trace
      console.warn(`[DKIM] Warning: DNS error for selector '${selector}' on domain '${domain}': ${error?.message || error}`);
      return { selector, domain, valid: false, error: error?.message || 'DNS error' };
    }
  }
}
