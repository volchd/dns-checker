import { resolveTxt, resolveMx, resolveCname, resolveA, resolveAAAA } from './dns-resolver';

// Patch the global dns object to use our custom resolver
export function patchMailAuth() {
  // Save the original dns object if it exists
  const originalDns = (globalThis as any).dns || {};
  
  // Create a custom dns implementation
  const customDns = {
    ...originalDns,
    
    resolveTxt: async (hostname: string, callback: (err: Error | null, addresses?: string[][]) => void) => {
      try {
        const records = await resolveTxt(hostname);
        callback(null, records);
      } catch (err) {
        callback(err as Error);
      }
    },
    
    resolveMx: async (hostname: string, callback: (err: Error | null, addresses?: Array<{ exchange: string, priority: number }>) => void) => {
      try {
        const records = await resolveMx(hostname);
        callback(null, records);
      } catch (err) {
        callback(err as Error);
      }
    },
    
    resolveCname: async (hostname: string, callback: (err: Error | null, addresses?: string[]) => void) => {
      try {
        const records = await resolveCname(hostname);
        callback(null, records);
      } catch (err) {
        callback(err as Error);
      }
    },
    
    // Keep the original resolve method if it exists
    resolve: originalDns.resolve || (() => {})
  };
  
  // Patch the global dns object
  (globalThis as any).dns = customDns;
  
  // Patch the process object if it doesn't exist
  if (typeof (globalThis as any).process === 'undefined') {
    (globalThis as any).process = {
      env: {},
      nextTick: (callback: () => void) => setTimeout(callback, 0)
    };
  }
  
  // Patch the net module if it doesn't exist
  if (typeof (globalThis as any).net === 'undefined') {
    (globalThis as any).net = {
      isIP: (addr: string) => {
        // Simple IPv4 regex
        if (/^(\d{1,3}\.){3}\d{1,3}$/.test(addr)) {
          return 4;
        }
        // Simple IPv6 regex (not exhaustive)
        if (/^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/.test(addr)) {
          return 6;
        }
        return 0;
      }
    };
  }
  
  // Patch the dns.lookup method if it doesn't exist
  if (!customDns.lookup) {
    customDns.lookup = async (
      hostname: string,
      optionsParam: Record<string, unknown> | number | ((err: Error | null, address?: string, family?: number) => void),
      callbackParam: ((err: Error | null, address?: string, family?: number) => void) | Record<string, unknown> | undefined
    ) => {
      let actualCallback: (err: Error | null, address?: string, family?: number) => void;
      let family: number | undefined = 0; // Default to 0 (any)
      let all = false;

      if (typeof optionsParam === 'function') {
        actualCallback = optionsParam as (err: Error | null, address?: string, family?: number) => void;
      } else if (typeof callbackParam === 'function'){
        actualCallback = callbackParam as (err: Error | null, address?: string, family?: number) => void;
        if (typeof optionsParam === 'number') {
          family = optionsParam;
        } else if (typeof optionsParam === 'object' && optionsParam !== null) {
          family = (optionsParam as { family?: number }).family;
          all = (optionsParam as { all?: boolean }).all || false;
        }
      } else {
        // This case should ideally not happen with correct usage of dns.lookup
        console.error('[DNS Patch] Invalid arguments to customDns.lookup');
        return;
      }

      // Node's dns.lookup with all:true returns an array of objects
      // For simplicity, this patch will still return the first found address if all is false (matching old behavior)
      // A more complete 'all:true' implementation would collect all A and AAAA records.
      // This simplified version for 'all:true' will try to return one of A or AAAA.
      if (all) {
         console.warn('[DNS Patch] customDns.lookup all:true is not fully implemented, will return first available A/AAAA record.');
         // Fallthrough to standard logic for now, which returns one address.
         // A proper 'all:true' would involve calling resolveA and resolveAAAA and combining results.
      }

      try {
        if (family === 6) {
          const addresses = await resolveAAAA(hostname);
          if (addresses.length > 0) {
            actualCallback(null, addresses[0], 6);
            return;
          }
          // If family 6 was explicitly requested and no AAAA found, error out.
          actualCallback(new Error(`No AAAA records found for ${hostname} when family 6 was specified.`));
          return;
        }

        // Try A records if family is 4 or 0 (any)
        if (family === 4 || family === 0 || family === undefined) {
          const addressesA = await resolveA(hostname);
          if (addressesA.length > 0) {
            actualCallback(null, addressesA[0], 4);
            return;
          }
          // If A records failed and family was 4 (explicitly), error out
          if (family === 4) {
             actualCallback(new Error(`No A records found for ${hostname} when family 4 was specified.`));
             return;
          }
        }

        // If family was 0 (any) and A records failed, try AAAA as a fallback
        if (family === 0 || family === undefined) {
          const addressesAAAA = await resolveAAAA(hostname);
          if (addressesAAAA.length > 0) {
            actualCallback(null, addressesAAAA[0], 6);
            return;
          }
        }
        
        // If all attempts fail
        actualCallback(new Error(`Could not resolve ${hostname} to an IP address.`));

      } catch (err) {
        if (err instanceof Error) {
          actualCallback(err);
        } else {
          actualCallback(new Error(`Unknown error during DNS lookup for ${hostname}`));
        }
      }
    };
  }
}
