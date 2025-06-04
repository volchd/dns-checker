import { resolveTxt } from './dns-resolver';

// Local copy of DMARCResult interface to avoid TS2306 error
export interface DMARCResult {
  valid: boolean;
  policy?: string;
  record?: string;
  error?: Error;
}

const DMARC_PREFIX = 'v=DMARC1';

function parseDMARCRecord(record: string): { valid: boolean; policy?: string; error?: string } {
  if (!record || typeof record !== 'string' || !record.trim().toLowerCase().startsWith(DMARC_PREFIX.toLowerCase())) {
    return { valid: false, error: 'Record does not start with v=DMARC1' };
  }
  const tags = record.split(';').map(t => t.trim()).filter(Boolean);
  const tagMap: Record<string, string> = {};
  for (const tag of tags) {
    const [key, ...rest] = tag.split('=');
    if (key && rest.length > 0) {
      tagMap[key.trim()] = rest.join('=').trim();
    }
  }
  if (!tagMap['p']) {
    return { valid: false, error: 'Missing required policy (p=) tag' };
  }
  const policy = tagMap['p'];
  if (!['none', 'quarantine', 'reject'].includes(policy)) {
    return { valid: false, error: `Invalid policy value: ${policy}` };
  }
  return { valid: true, policy };
}

export async function validateDMARC(domain: string): Promise<DMARCResult> {
  const dmarcDomain = `_dmarc.${domain}`;
  try {
    const txtRecords = await resolveTxt(dmarcDomain);
    const flatRecords = txtRecords.map(r => r.join('')).join('\n');
    const match = flatRecords.match(/v=DMARC1\s*;[^\n]+/i);
    if (!match) {
      return { valid: false, error: new Error('No DMARC record found') };
    }
    const record = match[0];
    const parsed = parseDMARCRecord(record);
    if (!parsed.valid) {
      return { valid: false, record, error: new Error(parsed.error || 'Invalid DMARC record') };
    }
    return { valid: true, policy: parsed.policy, record };
  } catch (error: any) {
    if (typeof error?.message === 'string' && error.message.includes('status 3')) {
      return { valid: false, error: new Error('No DMARC record found (NXDOMAIN)') };
    } else {
      return { valid: false, error: new Error(error?.message || 'DNS error') };
    }
  }
}
