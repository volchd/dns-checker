import { resolveTxt } from './dns-resolver';
import { SPFValidationResult, SPFRecord } from '../types/spf';

const SPF_PREFIX = 'v=spf1';
// Maximum number of DNS lookups allowed (SPF limit is 10)
const MAX_DNS_LOOKUPS = 10;
// Maximum recursion depth for includes/redirects
const MAX_RECURSION_DEPTH = 5;
// Maximum number of includes/redirects to process
const MAX_INCLUDES = 10;
// Maximum length of any domain or mechanism
const MAX_MECHANISM_LENGTH = 255;

// Helper function to validate domain name format
function isValidDomain(domain: string): boolean {
  if (!domain || typeof domain !== 'string') return false;
  
  // Check for common issues that could cause malformed domains
  if (domain.includes('[') || domain.includes(']') || 
      domain.includes(' ') || domain.includes('\t') ||
      domain.includes('\n') || domain.includes('\r')) {
    return false;
  }
  
  // More strict domain validation
  // 1. Must not start or end with a dot
  if (domain.startsWith('.') || domain.endsWith('.')) {
    return false;
  }
  
  // 2. Must have at least one dot and not too long (max 253 chars)
  if (domain.length > 253 || !domain.includes('.')) {
    return false;
  }
  
  // 3. Each label must be 1-63 chars, start/end with alphanumeric, and contain only alphanumeric and hyphens
  const labelRegex = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/i;
  return domain.split('.').every(label => {
    // Check label length and format
    return label.length > 0 && label.length <= 63 && labelRegex.test(label);
  });
}

// Helper to clean up domain from potential malformed input
function cleanDomain(domain: string): string | null {
  if (!domain) return null;
  
  // Remove any surrounding brackets, quotes, or whitespace
  let cleaned = domain.trim()
    .replace(/^\[|\]$/g, '') // Remove surrounding brackets
    .replace(/^"|"$/g, '')   // Remove surrounding quotes
    .trim();
    
  // If the domain is still not valid after cleaning, return null
  return isValidDomain(cleaned) ? cleaned : null;
}

// Helper function to add timeout to promises
const withTimeout = <T>(promise: Promise<T>, ms: number, timeoutMessage: string): Promise<T> => {
  let timeoutId: ReturnType<typeof setTimeout>;
  const timeoutPromise = new Promise<never>((_, reject) => {
    timeoutId = setTimeout(() => reject(new Error(timeoutMessage)), ms);
  });
  
  return Promise.race([
    promise.finally(() => clearTimeout(timeoutId)),
    timeoutPromise
  ]);
};

export async function validateSPF(
  domain: string, 
  depth: number = 0, 
  parentDomains: Set<string> = new Set(),
  includeCount: number = 0
): Promise<SPFValidationResult> {
  // Track the total number of includes/redirects processed
  if (includeCount > MAX_INCLUDES) {
    return {
      isValid: false,
      record: null,
      errors: [`Maximum number of includes/redirects (${MAX_INCLUDES}) exceeded`],
      warnings: [],
      dnsLookupCount: 0,
      includes: [],
      redirects: [],
      allMechanisms: []
    };
  }
  // Clean and validate the input domain first
  const cleanDomainName = cleanDomain(domain);
  if (!cleanDomainName) {
    return {
      isValid: false,
      record: null,
      errors: [`Invalid domain format: ${domain}`],
      warnings: [],
      dnsLookupCount: 0,
      includes: [],
      redirects: [],
      allMechanisms: []
    };
  }
  
  // Use the cleaned domain for all further operations
  domain = cleanDomainName;
  const result: SPFValidationResult = {
    isValid: true,
    record: null,
    errors: [],
    warnings: [],
    dnsLookupCount: 0,
    includes: [],
    redirects: [],
    allMechanisms: []
  };

  // Prevent infinite recursion and invalid domains
  if (depth > MAX_RECURSION_DEPTH) {
    return {
      isValid: false,
      record: null,
      errors: [`Maximum recursion depth (${MAX_RECURSION_DEPTH}) exceeded`],
      warnings: [],
      dnsLookupCount: 0,
      includes: [],
      redirects: [],
      allMechanisms: []
    };
  }

  // Check for circular references using the cleaned domain
  if (parentDomains.has(domain)) {
    return {
      isValid: false,
      record: null,
      errors: [`Circular reference detected in SPF records: ${Array.from(parentDomains).join(' -> ')} -> ${domain}`],
      warnings: [],
      dnsLookupCount: 0,
      includes: [],
      redirects: [],
      allMechanisms: []
    };
  }

  // Create a new set for this validation to track the chain
  const currentDomains = new Set(parentDomains).add(domain);

  try {
    return await withTimeout(
      (async () => {

        // 1. Check SPF Record Existence
        const txtRecords = await resolveTxt(domain);
    const spfRecords = txtRecords.flat().filter(record => 
      typeof record === 'string' && record.trim().startsWith(SPF_PREFIX)
    );

    if (spfRecords.length === 0) {
      result.errors.push('No SPF record found');
      result.isValid = false;
      return result;
    }

    // 2. Check for multiple SPF records
    if (spfRecords.length > 1) {
      result.errors.push('Multiple SPF records found. Only one SPF record is allowed per domain');
      result.isValid = false;
    }

    const spfRecord = spfRecords[0];
    result.record = spfRecord;
    result.dnsLookupCount++;

    // 3. Parse SPF record
    const parsedRecord = parseSPFRecord(spfRecord);
    if (!parsedRecord) {
      result.errors.push('Invalid SPF record format');
      result.isValid = false;
      return result;
    }

    // 4. Check DNS lookup count
    if (result.dnsLookupCount > MAX_DNS_LOOKUPS) {
      result.errors.push(`Exceeded maximum of ${MAX_DNS_LOOKUPS} DNS lookups`);
      result.isValid = false;
    }

    // Process includes
    for (const include of parsedRecord.mechanisms.include) {
      try {
        if (includeCount >= MAX_INCLUDES) {
          result.errors.push(`Maximum number of includes/redirects (${MAX_INCLUDES}) reached`);
          result.isValid = false;
          break;
        }
        
        const includeResult = await validateSPF(include, depth + 1, currentDomains, includeCount + 1);
        result.includes.push({
          domain: include,
          result: includeResult
        });
        result.dnsLookupCount += includeResult.dnsLookupCount;
        
        if (!includeResult.isValid) {
          result.errors.push(`Include for ${include} failed validation`);
          result.isValid = false;
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        result.errors.push(`Failed to validate include: ${include} (${errorMessage})`);
        result.isValid = false;
      }
    }
    
    // Process redirect (only if we haven't hit the include limit)
    let hasEffectiveRedirect = false;
    if (result.isValid && parsedRecord.mechanisms.redirect) {
      try {
        if (includeCount >= MAX_INCLUDES) {
          result.errors.push(`Maximum number of includes/redirects (${MAX_INCLUDES}) reached`);
          result.isValid = false;
        } else {
          const redirectDomain = parsedRecord.mechanisms.redirect;
          const redirectResult = await validateSPF(
            redirectDomain,
            depth + 1,
            currentDomains,
            includeCount + 1
          );

          result.redirects.push({
            domain: redirectDomain,
            result: redirectResult
          });
          result.dnsLookupCount += redirectResult.dnsLookupCount;

          // If the redirect target itself is invalid (e.g., syntax error, too many lookups in its own chain),
          // then the current record that redirects to it is also considered to have an invalid SPF setup in terms of policy enforcement.
          if (!redirectResult.isValid) {
            result.errors.push(`Redirect to ${redirectDomain} failed validation (target record invalid or led to error)`);
            result.isValid = false; // Mark current result as invalid due to redirect failure
          } else {
            // If redirect is structurally valid and its record is valid, its 'all' mechanism is the effective one.
            // The recursive call to validateSPF ensures redirectResult.allMechanisms itself contains only the 'all' string.
            result.allMechanisms = [...redirectResult.allMechanisms]; // Propagate the 'all' mechanism from the redirect target
            hasEffectiveRedirect = true;
            result.warnings.push(...redirectResult.warnings.map(w => `Redirect (${redirectDomain}): ${w}`));
          }
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        result.errors.push(`Failed to validate redirect: ${parsedRecord.mechanisms.redirect} (${errorMessage})`);
        result.isValid = false;
      }
    }

    // 5. Set the 'allMechanisms' to be ONLY the effective 'all' string.
    if (!hasEffectiveRedirect) {
      // If there was no effective redirect, use the 'all' mechanism from the current record.
      if (parsedRecord.mechanisms.all) {
        result.allMechanisms = [parsedRecord.mechanisms.all];
      } else {
        result.allMechanisms = []; // No 'all' mechanism found in this record and no redirect
      }
    }
    // If hasEffectiveRedirect is true, result.allMechanisms was already set from redirectResult.allMechanisms.

        return result;
      })(),
      15000, // 15 second timeout
      `SPF validation timed out for ${domain} after 15 seconds`
    );
  } catch (error) {
    let errorMessage = 'Unknown error during SPF validation';
    if (error instanceof Error) {
      errorMessage = error.message;
      console.error(`SPF validation error for ${domain}:`, error);
    }
    return {
      isValid: false,
      record: null,
      errors: [errorMessage],
      warnings: [],
      dnsLookupCount: 0,
      includes: [],
      redirects: [],
      allMechanisms: []
    };
  }
}

function parseSPFRecord(record: string): SPFRecord | null {
  if (!record || typeof record !== 'string' || !record.trim().startsWith(SPF_PREFIX)) {
    return null;
  }

  const result: SPFRecord = {
    raw: record,
    version: SPF_PREFIX,
    mechanisms: {
      all: null, // Default to null, explicitly set if found
      ip4: [],
      ip6: [],
      a: [],
      mx: [],
      include: [],
      exists: [],
      redirect: null,
      exp: null
    },
    modifiers: {}
  };

  const parts = record
    .substring(SPF_PREFIX.length)
    .trim()
    .split(/\s+/)
    .filter(part => part.trim() !== '');

  for (const part of parts) {
    if (!part) continue;

    try {
      const mechanismMatch = part.match(/^([+~?-]?)([a-zA-Z0-9._-]+)(?:[:=](.+))?$/);

      if (!mechanismMatch) {
        if (part.includes('=') && !part.toLowerCase().startsWith('exp=')) {
            const [key, val] = part.split('=');
            const cleanKey = key?.trim().toLowerCase();
            const cleanVal = val?.trim();
            if (cleanKey && cleanVal) {
                result.modifiers[cleanKey] = cleanVal;
            }
        }
        continue;
      }

      const [_, qualifier, type, value] = mechanismMatch;
      const mechName = type.toLowerCase();
      const cleanValue = value ? value.trim() : '';

      switch (mechName) {
        case 'all':
          result.mechanisms.all = (qualifier || '+') + 'all';
          break;

        case 'ip4':
          if (cleanValue && isValidIPv4(cleanValue)) {
            result.mechanisms.ip4.push(cleanValue);
          }
          break;

        case 'ip6':
          if (cleanValue && isValidIPv6(cleanValue)) {
            result.mechanisms.ip6.push(cleanValue);
          }
          break;

        case 'a':
        case 'mx':
          const domainSpecForAMx: string = cleanValue.split('/')[0];
          if (!domainSpecForAMx || isValidDomain(domainSpecForAMx)) {
            result.mechanisms[mechName].push(cleanValue || ''); // Store the full value (e.g., domain or domain/cidr)
          }
          break;

        case 'include':
        case 'exists':
          if (cleanValue) {
            const domainSpecForIncludeExists: string = cleanValue.split('/')[0];
            if (isValidDomain(domainSpecForIncludeExists)) {
              if (domainSpecForIncludeExists.length <= MAX_MECHANISM_LENGTH) {
                result.mechanisms[mechName].push(cleanValue);
              }
            }
          }
          break;

        case 'redirect':
          if (cleanValue) {
            const domainSpecForRedirect: string = cleanValue.split('/')[0];
            if (isValidDomain(domainSpecForRedirect)) {
              if (domainSpecForRedirect.length <= MAX_MECHANISM_LENGTH) {
                result.mechanisms.redirect = cleanValue;
              }
            }
          }
          break;

        case 'exp':
          if (cleanValue) {
            result.mechanisms.exp = cleanValue; // Store only the value for exp mechanism
          }
          break;

        default:
          // console.warn(`Unknown or unhandled SPF mechanism part: ${part}`);
          break;
      }
    } catch (error) {
      console.warn(`Error parsing SPF part: ${part}`, error);
      continue;
    }
  }
  return result;
}

// Helper function to validate IPv4 addresses
function isValidIPv4(ip: string): boolean {
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\/([0-9]|[12][0-9]|3[0-2]))?$/;
  return ipv4Regex.test(ip);
}

// Helper function to validate IPv6 addresses (simplified)
function isValidIPv6(ip: string): boolean {
  // This is a simplified version - in production, use a more comprehensive IPv6 validator
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))(\/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))?$/;
  return ipv6Regex.test(ip);
}

// Helper function to get detailed SPF validation results
export async function getSPFDetails(domain: string): Promise<{
  validation: SPFValidationResult;
  includedRecords: Record<string, SPFValidationResult>;
  redirectRecords: Record<string, SPFValidationResult>;
}> {
  const validation = await validateSPF(domain);
  const includedRecords: Record<string, SPFValidationResult> = {};
  const redirectRecords: Record<string, SPFValidationResult> = {};

  // Process includes (they're already validated in the main validation)
  for (const include of validation.includes) {
    includedRecords[include.domain] = include.result;
  }

  // Process redirects (they're already validated in the main validation)
  for (const redirect of validation.redirects) {
    redirectRecords[redirect.domain] = redirect.result;
  }

  return {
    validation,
    includedRecords,
    redirectRecords
  };
}
