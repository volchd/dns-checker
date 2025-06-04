import { validateSPF } from './utils/spf-validator';
import type { SPFValidationResult } from './types/spf';
import { validateDKIM } from './utils/dkim-validator';
import { validateDMARC } from './utils/dmarc-validator';
import type { DKIMValidationResult } from './types/dkim';
import { calculateScore } from './utils/scoring';


// Interface for DNS response from Cloudflare's DNS-over-HTTPS API
interface DnsResponse {
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean;
  CD: boolean;
  Question: Array<{
    name: string;
    type: number;
  }>;
  Answer?: Array<{
    name: string;
    type: number;
    TTL: number;
    data: string;
  }>;
  Comment?: string;
}

// Interface for the email authentication check result
type EmailAuthResult = {
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
  mtaSts: {
    valid: boolean;
    mode?: string;
    mx?: string[];
    error?: string;
  };
  tlsRpt: {
    valid: boolean;
    rua?: string[];
    error?: string;
  };
};

/**
 * Query DNS records using Cloudflare's DNS-over-HTTPS API
 */
async function queryDns(domain: string, type: 'TXT' | 'MX' | 'CNAME' | 'A'): Promise<string[][]> {
  try {
    const response = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`,
      {
        headers: { 
          'Accept': 'application/dns-json',
          'User-Agent': 'EmailAuthChecker/1.0',
        },
        cf: {
          // Tell Cloudflare to cache the response for 5 minutes
          cacheTtl: 300,
          cacheEverything: true,
        },
      }
    );

    if (!response.ok) {
      // Handle rate limiting or other HTTP errors
      if (response.status === 429) {
        throw new Error('DNS query rate limit exceeded. Please try again later.');
      }
      throw new Error(`DNS query failed: ${response.status} ${response.statusText}`);
    }

    const data: DnsResponse = await response.json();

    // Handle NXDOMAIN (non-existent domain) and other DNS errors
    if (data.Status !== 0) {
      // NXDOMAIN - Domain doesn't exist
      if (data.Status === 3) {
        return [];
      }
      throw new Error(`DNS query returned error: ${data.Comment || `Status: ${data.Status}`}`);
    }

    // No records found is not an error, just return empty array
    if (!data.Answer || data.Answer.length === 0) {
      return [];
    }

    try {
      // Process the response based on record type
      if (type === 'TXT') {
        return data.Answer.map((answer) => {
          // Handle malformed TXT records gracefully
          try {
            // Remove surrounding quotes and split if there are multiple strings in one TXT record
            const content = String(answer.data || '').replace(/^"/, '').replace(/"$/, '');
            return content.split('" "');
          } catch (e) {
            console.warn(`Error processing TXT record for ${domain}:`, e);
            return [String(answer.data || '')];
          }
        });
      } else {
        // For MX and CNAME, return an array with a single array containing the record
        return [data.Answer.map((answer) => String(answer.data || ''))];
      }
    } catch (parseError) {
      console.error(`Error parsing DNS response for ${domain} (${type}):`, parseError);
      throw new Error(`Failed to parse DNS response: ${parseError instanceof Error ? parseError.message : 'Unknown error'}`);
    }
  } catch (error) {
    // Don't log NXDOMAIN as an error - it's a normal case
    if (!(error instanceof Error && error.message.includes('Status: 3'))) {
      console.error(`DNS query error for ${domain} (${type}):`, error);
    }
    // Re-throw the error with more context
    throw new Error(`Failed to query ${type} records for ${domain}: ${error instanceof Error ? error.message : 'Unknown error'}`);
  }
}

/**
 * Validate a domain name format
 */
function isValidDomain(domain: string): boolean {
  // Simple domain validation - can be enhanced as needed
  return /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$/i.test(domain);
}

/**
    const policy = policyMatch[1].toLowerCase();
    const validPolicies = ['none', 'quarantine', 'reject'];
    
    return {
      valid: validPolicies.includes(policy),
      policy
    };
  } catch (error) {
    console.error('Error parsing DMARC record:', error);
    return { valid: false };
  }
}

/**
 * Main worker handler
 */
export default {
  async fetch(request: Request): Promise<Response> {
    // Set CORS headers
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        headers: corsHeaders,
      });
    }

    // Only allow GET requests
    if (request.method !== 'GET') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders,
        },
      });
    }

    // Parse the domain from the URL
    const url = new URL(request.url);
    const domain = url.searchParams.get('domain');

    // Validate the domain parameter
    if (!domain) {
      return new Response(
        JSON.stringify({ error: 'Domain parameter is required' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    if (!isValidDomain(domain)) {
      return new Response(
        JSON.stringify({ error: 'Invalid domain format' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Check if the domain exists via DNS A-record lookup
    const aRecords = await queryDns(domain, 'A');
    if (!aRecords || aRecords.length === 0) {
      return new Response(
        JSON.stringify({ error: `Domain '${domain}' does not exist (no DNS A record found)` }),
        { status: 404, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    try {
      console.log(`Starting email authentication check for domain: ${domain}`);
      
      // Initialize result object
      const result: EmailAuthResult = {
        spf: { valid: false },
        dkim: { valid: false, selectors: [] },
        dmarc: { valid: false },
        mtaSts: { valid: false },
        tlsRpt: { valid: false },
      };

      // Check SPF with detailed validation
      try {
        const spfValidation = await validateSPF(domain);
        
        // Helper function to flatten includes/redirects for the simplified response
        const flattenIncludes = (includes: Array<{ domain: string; result: SPFValidationResult }>): string[] => {
          return includes.map(inc => `${inc.domain}${inc.result.record ? ' (valid)' : ' (invalid)'}`);
        };
        
        result.spf = {
          valid: spfValidation.isValid,
          record: spfValidation.record || undefined,
          error: spfValidation.errors.length > 0 ? spfValidation.errors.join('; ') : undefined,
          details: {
            dnsLookupCount: spfValidation.dnsLookupCount,
            includes: flattenIncludes(spfValidation.includes),
            redirects: spfValidation.redirects.map(r => r.domain),
            allMechanisms: spfValidation.allMechanisms,
            warnings: spfValidation.warnings,
            errors: spfValidation.errors
          }
        };
        
        // Process any redirects
        if (spfValidation.redirects.length > 0) {
          for (const redirect of spfValidation.redirects) {
            try {
              if (!result.spf.details) {
                result.spf.details = {
                  dnsLookupCount: 0,
                  includes: [],
                  redirects: [],
                  allMechanisms: [],
                  warnings: [],
                  errors: []
                };
              }
              
              // Add the redirect result to the response
              result.spf.details.redirects.push(
                `[${redirect.domain}]: ${redirect.result.record || 'No record found'}`
              );
              
              // If the redirect failed, add its errors
              if (redirect.result.errors.length > 0) {
                result.spf.details.errors.push(
                  ...redirect.result.errors.map(e => `Redirect ${redirect.domain}: ${e}`)
                );
              }
              
              // Add any warnings from the redirect
              if (redirect.result.warnings.length > 0) {
                result.spf.details.warnings.push(
                  ...redirect.result.warnings.map(w => `Redirect ${redirect.domain}: ${w}`)
                );
              }
            } catch (redirectError) {
              const errorMessage = redirectError instanceof Error ? redirectError.message : 'Unknown error';
              if (result.spf.details) {
                result.spf.details.errors.push(`Error processing redirect ${redirect.domain}: ${errorMessage}`);
              }
            }
          }
        }
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : 'Unknown error during SPF validation';
        result.spf = {
          valid: false,
          error: `Error validating SPF: ${errorMessage}`,
          details: {
            dnsLookupCount: 0,
            includes: [],
            redirects: [],
            allMechanisms: [],
            warnings: [],
            errors: [errorMessage]
          }
        };
      }

      // Check DMARC (using the new utility)
      try {
        const dmarcResult = await validateDMARC(domain);
        result.dmarc = {
          valid: dmarcResult.valid,
          record: dmarcResult.record,
          policy: dmarcResult.policy,
          error: dmarcResult.error ? (dmarcResult.error instanceof Error ? dmarcResult.error.message : String(dmarcResult.error)) : undefined
        };
      } catch (error) {
        console.error('DMARC check failed:', error);
        result.dmarc.error = error instanceof Error ? error.message : 'Unknown error';
      }

      // Check DKIM (using common selectors and the DKIM validator)
      const commonSelectors = [
        'default', 'google', 'selector1', 'selector2', 'k1', 'mx',
        'dkim', 's1', 's2', 'mx1', 'mx2', 'fm1', 'fm2', 'k2', 'protonmail',
        'everlytickey1', 'everlytickey2', 'mail', 'mail1', 'mail2'
      ];
      
      const dkimResults: DKIMValidationResult[] = [];
      let foundValidDKIM = false;
      let firstError: string | undefined = undefined;
      for (const selector of commonSelectors) {
        const dkimResult = await validateDKIM(selector, domain);
        dkimResults.push(dkimResult);
        if (dkimResult.valid && !foundValidDKIM) {
          foundValidDKIM = true;
        }
        if (dkimResult.error && !firstError) {
          firstError = dkimResult.error;
        }
      }
      // Sort selectors: valid ones first, then invalid
      const sortedDkimResults = dkimResults.sort((a, b) => (a.valid === b.valid ? 0 : a.valid ? -1 : 1));
      result.dkim = {
        valid: foundValidDKIM,
        selectors: sortedDkimResults,
        error: foundValidDKIM ? undefined : firstError
      };
      // Optionally, for compatibility, you can still set selector/record of the first valid one:
      if (foundValidDKIM) {
        const firstValid = dkimResults.find(r => r.valid);
        if (firstValid) {
          result.dkim.selector = firstValid.selector;
          result.dkim.record = firstValid.record;
        }
      }
      

      // Check MTA-STS (simplified check)
      try {
        const mtaStsRecords = await queryDns(`_mta-sts.${domain}`, 'TXT');
        const mtaStsRecord = mtaStsRecords.flat().find(record => record.startsWith('v=STSv1'));
        
        if (mtaStsRecord) {
          // Simplified MTA-STS check - just verify the record exists
          result.mtaSts = {
            valid: true,
            mode: mtaStsRecord.includes('p=reject') ? 'enforce' : 
                  mtaStsRecord.includes('p=testing') ? 'testing' : 'none'
          };
        } else {
          result.mtaSts.error = 'No MTA-STS record found';
        }
      } catch (error) {
        console.error('MTA-STS check failed:', error);
        result.mtaSts.error = error instanceof Error ? error.message : 'Unknown error';
      }

      // Check TLS-RPT (simplified check)
      try {
        const tlsRptRecords = await queryDns(`_smtp._tls.${domain}`, 'TXT');
        const tlsRptRecord = tlsRptRecords.flat().find(record => record.startsWith('v=TLSRPTv1'));
        
        if (tlsRptRecord) {
          // Extract RUA (reporting URI) if present
          const ruaMatch = tlsRptRecord.match(/rua=([^;\s]+)/i);
          const rua = ruaMatch ? [ruaMatch[1].toLowerCase()] : undefined;
          
          result.tlsRpt = {
            valid: true,
            rua
          };
        } else {
          result.tlsRpt.error = 'No TLS-RPT record found';
        }
      } catch (error) {
        console.error('TLS-RPT check failed:', error);
        result.tlsRpt.error = error instanceof Error ? error.message : 'Unknown error';
      }

      console.log(`Email authentication check completed for domain: ${domain}`);
      
      // Calculate compliance score and add to response
      const score = calculateScore(result);
      // Place score at the beginning of the response
      const responseWithScoreFirst = { score, ...result };
      return new Response(JSON.stringify(responseWithScoreFirst, null, 2), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          ...corsHeaders,
        },
      });
    } catch (error) {
      console.error('Error processing request:', error);
      return new Response(
        JSON.stringify({
          error: 'Internal server error',
          message: error instanceof Error ? error.message : 'Unknown error',
        }),
        {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
          },
        }
      );
    }
  },
};
