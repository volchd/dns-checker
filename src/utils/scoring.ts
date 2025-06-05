// Scoring logic for SPF, DKIM, and DMARC compliance (refined scoring model)
import type { DKIMValidationResult } from '../types/dkim';

// Redefine EmailAuthResult type locally for scoring to avoid circular import
export type EmailAuthResult = {
  spf: {
    valid: boolean;
    record?: string;
    error?: string;
    details?: {
      dnsLookupCount: number;
      includes: string[];
      redirects: string[];
      allMechanisms: string[];
      warnings: string[];
      errors: string[];
    };
  };
  dkim: {
    valid: boolean;
    selectors: DKIMValidationResult[];
    selector?: string;
    record?: string;
    error?: string;
    details?: {
      selectorsChecked: string[];
      errors: string[];
    };
  };
  dmarc: {
    valid: boolean;
    record?: string;
    policy?: string;
    error?: string;
  };
};
export interface ScoreBreakdown {
  total: number;
  spf: number;
  dkim: number;
  dmarc: number;
  details: Record<string, number>;
  reasons: Record<string, string>;
  recommendations: Record<string, string>;
}

/**
 * Refined scoring model:
 * SPF: 0-30, DKIM: 0-30, DMARC: 0-40
 * - SPF: 30/30 for valid with -all, 28/30 for ~all, 0 for +all or missing
 * - DKIM: 30/30 for valid/2048bit+, 28/30 for valid/1024bit, 0 for missing/invalid/weak
 * - DMARC: 40/40 for p=reject, 38/40 for p=quarantine, 20/40 for p=none, 0 for missing/invalid
 * Any critical misconfig (missing SPF/DKIM/DMARC, SPF +all, DKIM <1024bit) = "Poor" (<70)
 */
export function calculateScore(result: EmailAuthResult): ScoreBreakdown {
  const reasons: Record<string, string> = {};
  const recommendations: Record<string, string> = {};
  let total = 0;
  let spfScore = 0;
  let dkimScore = 0;
  let dmarcScore = 0;
  let bonusScore = 0;
  const details: Record<string, number> = {};

  // ----- SPF (max 30) -----
  let spfValid = result.spf && result.spf.valid && typeof result.spf.record === 'string' && result.spf.record.includes('v=spf1');
  if (spfValid) {
    spfScore += 10; // SPF Record Exists
    details['spf_exists'] = 10;
    // Proper SPF Syntax
    if (!result.spf.error && (!result.spf.details || !result.spf.details.errors || result.spf.details.errors.length === 0)) {
      spfScore += 5;
      details['spf_syntax'] = 5;
    } else {
      details['spf_syntax'] = 0;
      reasons['spf'] = 'SPF record has syntax errors.';
      recommendations['spf'] = 'Fix SPF syntax errors to ensure proper evaluation.';
    }
    // Check for all mechanism
    let allMech = '';
    if (result.spf.details && result.spf.details.allMechanisms) {
      allMech = result.spf.details.allMechanisms.find((m: string) => /[-~?+]all/.test(m)) || '';
    }
    if (allMech.startsWith('-all')) {
      spfScore += 10;
      details['spf_all'] = 10;
      reasons['spf'] = 'SPF uses strict "-all" policy.';
      recommendations['spf'] = 'No change needed. This is optimal.';
    } else if (allMech.startsWith('~all')) {
      spfScore += 8;
      details['spf_all'] = 8;
      reasons['spf'] = 'SPF uses softfail "~all" policy.';
      recommendations['spf'] = 'Consider switching to strict "-all" for maximum protection.';
    } else if (allMech.startsWith('+all')) {
      details['spf_all'] = 0;
      spfScore -= 5; // Deduct for +all
      details['spf_no_plusall'] = 0;
      reasons['spf'] = 'SPF uses permissive "+all" which is insecure.';
      recommendations['spf'] = 'Remove or replace "+all" with "-all" or "~all" to prevent spoofing.';
    } else {
      details['spf_all'] = 0;
      reasons['spf'] = 'SPF record does not specify an "all" mechanism.';
      recommendations['spf'] = 'Add an "all" mechanism (preferably "-all") to define policy for all mail sources.';
    }
    // No "+all" (bonus if not present)
    if (allMech && !allMech.startsWith('+all')) {
      spfScore += 5;
      details['spf_no_plusall'] = 5;
    }
    // If not already set above, set generic reason/recommendation for SPF
    if (!reasons['spf']) {
      reasons['spf'] = 'SPF record is present and valid.';
      recommendations['spf'] = 'No change needed. This is optimal.';
    }
  } else {
    details['spf_exists'] = 0;
    details['spf_syntax'] = 0;
    details['spf_all'] = 0;
    details['spf_no_plusall'] = 0;
    spfScore = 0;
    reasons['spf'] = 'SPF record is missing or invalid.';
    recommendations['spf'] = 'Add a valid SPF record with proper syntax and a strict "-all" policy.';
  }

  // ----- DKIM (max 30 + 5 bonus) -----
  let dkimValid = result.dkim && Array.isArray(result.dkim.selectors) && result.dkim.selectors.length > 0 && result.dkim.selectors.some(sel => sel.valid && sel.record);
  if (dkimValid) {
    details['dkim_exists'] = 15;
    dkimScore += 15;
    // Key strength
    let maxKeyLen = 0;
    let validSelectorCount = 0;
    for (const sel of result.dkim.selectors) {
      if (sel.valid && sel.record) {
        validSelectorCount++;
        let bits = 0;
        const match = sel.record.match(/bits=(\d+)/);
        if (match && match[1]) {
          bits = parseInt(match[1], 10);
        } else {
          // fallback: check length of base64 key
          const key = sel.record.match(/p=([A-Za-z0-9+/=]+)/);
          if (key && key[1]) {
            const len = key[1].length * 6 / 8; // rough estimate
            if (len > 256) bits = 2048;
            else if (len > 128) bits = 1024;
            else bits = 512;
          }
        }
        if (bits > maxKeyLen) maxKeyLen = bits;
      }
    }
    if (maxKeyLen >= 1024) {
      dkimScore += 10;
      details['dkim_key_strength'] = 10;
      reasons['dkim'] = 'DKIM key strength is adequate (>=1024 bits).';
      recommendations['dkim'] = 'No change needed. This is industry standard.';
    } else {
      details['dkim_key_strength'] = 0;
      reasons['dkim'] = 'DKIM key strength is weak (<1024 bits).';
      recommendations['dkim'] = 'Upgrade DKIM keys to at least 1024 bits for security.';
    }
    // Bonus for multiple selectors
    if (result.dkim.selectors.length > 1) {
      bonusScore += 5;
      details['dkim_multiple_selectors_bonus'] = 5;
      reasons['dkim'] = 'Multiple DKIM selectors detected (key rotation enabled).';
      recommendations['dkim'] = 'No change needed. Key rotation is a best practice.';
    }
    // If not already set above, set generic reason/recommendation for DKIM
    if (!reasons['dkim']) {
      reasons['dkim'] = 'DKIM record is present and valid.';
      recommendations['dkim'] = 'No change needed. This is optimal.';
    }
  } else {
    details['dkim_exists'] = 0;
    details['dkim_key_strength'] = 0;
    details['dkim_multiple_selectors_bonus'] = 0;
    dkimScore = 0;
    reasons['dkim'] = 'DKIM record is missing or invalid.';
    recommendations['dkim'] = 'Add a valid DKIM record with at least 1024-bit key and enable key rotation if possible.';
  }

  // ----- DMARC (max 40 + 5 bonus) -----
  let dmarcValid = result.dmarc && result.dmarc.valid && typeof result.dmarc.record === 'string' && result.dmarc.record.includes('v=DMARC1');
  if (dmarcValid) {
    dmarcScore += 10;
    details['dmarc_exists'] = 10;
    if (result.dmarc.policy === 'reject') {
      dmarcScore += 20;
      details['dmarc_policy'] = 20;
      reasons['dmarc'] = 'DMARC policy is set to "reject" (full enforcement).';
      recommendations['dmarc'] = 'No change needed. This is optimal.';
    } else if (result.dmarc.policy === 'quarantine') {
      dmarcScore += 15;
      details['dmarc_policy'] = 15;
      reasons['dmarc'] = 'DMARC policy is set to "quarantine" (partial enforcement).';
      recommendations['dmarc'] = 'Consider upgrading DMARC policy to "reject" for full protection.';
    } else if (result.dmarc.policy === 'none') {
      dmarcScore += 5;
      details['dmarc_policy'] = 5;
      reasons['dmarc'] = 'DMARC policy is set to "none" (monitoring only).';
      recommendations['dmarc'] = 'Increase DMARC policy to "quarantine" or "reject" to enforce protection.';
    } else {
      details['dmarc_policy'] = 0;
      reasons['dmarc'] = 'DMARC policy is not set or unrecognized.';
      recommendations['dmarc'] = 'Set DMARC policy to "reject" or "quarantine" for enforcement.';
    }
    // Bonus for rua reporting
    if (typeof result.dmarc.record === 'string' && /rua=/i.test(result.dmarc.record)) {
      bonusScore += 5;
      details['dmarc_rua_bonus'] = 5;
      reasons['dmarc'] = 'DMARC reporting (rua) is enabled.';
      recommendations['dmarc'] = 'No change needed. Reporting is recommended.';
    }
    // If not already set above, set generic reason/recommendation for DMARC
    if (!reasons['dmarc']) {
      reasons['dmarc'] = 'DMARC record is present and valid.';
      recommendations['dmarc'] = 'No change needed. This is optimal.';
    }
  } else {
    details['dmarc_exists'] = 0;
    details['dmarc_policy'] = 0;
    details['dmarc_rua_bonus'] = 0;
    dmarcScore = 0;
    reasons['dmarc'] = 'DMARC record is missing or invalid.';
    recommendations['dmarc'] = 'Add a valid DMARC record with policy set to "reject" and enable rua reporting.';
  }

  // ----- Total and rating thresholds -----
  // Calculate final scores by summing up details
  spfScore = (details['spf_exists'] || 0) + 
             (details['spf_syntax'] || 0) + 
             (details['spf_all'] || 0) + 
             (details['spf_no_plusall'] || 0);

  dkimScore = (details['dkim_exists'] || 0) + 
              (details['dkim_key_strength'] || 0) + 
              (details['dkim_multiple_selectors_bonus'] || 0);  // Include bonus in dkim score

  dmarcScore = (details['dmarc_exists'] || 0) + 
               (details['dmarc_policy'] || 0) + 
               (details['dmarc_rua_bonus'] || 0);  // Include bonus in dmarc score

  // Calculate total (no separate bonus score needed)
  total = spfScore + dkimScore + dmarcScore;

  return {
    total,
    spf: spfScore,
    dkim: dkimScore,
    dmarc: dmarcScore,
    details,
    reasons,
    recommendations
  };
}
