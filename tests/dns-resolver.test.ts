import { describe, it, expect, vi, beforeEach, afterEach, type Mock } from 'vitest';
import {
  resolveA,
  resolveAAAA,
  resolveMx,
  resolveCname,
  resolveTxt,
} from '../src/utils/dns-resolver';

// Mock the global fetch function
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe('DNS Resolver', () => {
  // Helper to create a fetch mock that is sensitive to AbortSignal
  const createAbortableMockFetch = (
    successfulResponseData: any,
    status: number = 200,
    delay: number = 0, // This is the normal delay for successful/failed responses
    networkDelay: number = 10000 // This is the delay for simulating a non-responsive server for timeout tests
  ): Mock<[_input: RequestInfo | URL, _init?: RequestInit], Promise<Response>> => {
    return vi.fn((_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> => {
      const signal = _init?.signal;
      const actualDelay = signal && delay === Infinity ? networkDelay : delay;
      let isAbortedBySignal = false; // Flag to track if abort signal processed

      return new Promise((resolve, reject) => {
        const timerId = setTimeout(() => {
          if (isAbortedBySignal) { // If abort listener already ran, do nothing further.
            return;
          }
          // This block runs if the mock's own timer expires *before* an abort signal handled it.
          if (signal && delay === Infinity) {
            // When delay is Infinity, this timer firing means the abort signal was NOT processed as expected.
            // Do nothing here; the promise should only be rejected by the abortListener.
            // If the abortListener doesn't fire, the test will hang and time out via Vitest's own mechanism.
            return; // Prevent falling through to other resolve/reject paths
          } else if (status >= 200 && status < 300) {
            resolve(new Response(JSON.stringify(successfulResponseData), { status }));
          } else if (status === 0) { // Simulate network error
            reject(new TypeError('Network error'));
          } else { // Simulate server error for non-timeout-simulation paths
            reject(new Response(JSON.stringify(successfulResponseData), { status }));
          }
        }, actualDelay);

        if (signal) {
          const abortListener = () => {
            if (isAbortedBySignal) return; // Prevent multiple executions
            isAbortedBySignal = true;

            clearTimeout(timerId); // Crucial: stop the mock's own timer
            if (signal.removeEventListener) { // removeEventListener might not be on all AbortSignal impls in older envs, but good for modern ones
               signal.removeEventListener('abort', abortListener); // Clean up
            }
            reject(new DOMException('Aborted', 'AbortError')); // Reject due to abort signal
          };

          if (signal.aborted) {
            abortListener();
          } else {
            signal.addEventListener('abort', abortListener);
          }
        }
          // If aborted, handleAbort would have already rejected the promise.
        }); // This delay should be longer than the application's timeout
      });
  };

  beforeEach(() => {
    vi.useFakeTimers(); // Use fake timers for timeout tests
    mockFetch.mockReset(); // Reset fetch mock before each test
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers(); // Restore real timers after each test
  });

  // --- resolveA tests ---
  describe('resolveA', () => {
    it('should resolve A records successfully', async () => {
      const mockResponse = {
        Status: 0,
        Answer: [{ name: 'example.com', type: 1, TTL: 300, data: '192.0.2.1' }],
      };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
        text: async () => JSON.stringify(mockResponse),
      } as Response);

      const result = await resolveA('example.com');
      expect(result).toEqual(['192.0.2.1']);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://cloudflare-dns.com/dns-query?name=example.com&type=A',
        expect.anything()
      );
    });

    it('should throw an error for A record resolution failure (status not 0)', async () => {
      const mockResponse = { Status: 2 /* SERVFAIL */, Answer: [] };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
        text: async () => JSON.stringify(mockResponse),
      } as Response);

      await expect(resolveA('example.com')).rejects.toThrow('DNS A query failed for example.com');
    });

    it('should throw an error for invalid hostname in A record resolution', async () => {
      await expect(resolveA('')).rejects.toThrow('Invalid hostname for A query');
      const longHostname = 'a'.repeat(256);
      await expect(resolveA(longHostname)).rejects.toThrow('Invalid hostname for A query');
    });

    it('should handle NXDOMAIN for A records by throwing an error', async () => {
      const mockResponse = { Status: 3 /* NXDOMAIN */, Answer: [] };
       mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
        text: async () => JSON.stringify(mockResponse),
      } as Response);
      await expect(resolveA('nxdomain.example.com')).rejects.toThrow('DNS A query for nxdomain.example.com resulted in NXDOMAIN (status 3)');
    });

    it('should throw an error on A record resolution timeout', async () => {
      const mockSuccessfulResponse = { Status: 0, Answer: [{ name: 'example.com', type: 1, TTL: 300, data: '192.0.2.1' }] }; // Data it would return if not timed out
      mockFetch.mockImplementationOnce(createAbortableMockFetch(mockSuccessfulResponse, 200, Infinity));

      const promise = resolveA('example.com');
      vi.advanceTimersByTime(5001); // Default app timeout is 5000ms
      await vi.runAllTimersAsync(); // Ensure all timers and microtasks are processed

      let errorThrown: Error | null = null;
      try {
        await promise;
      } catch (e: any) {
        errorThrown = e;
      }
      expect(errorThrown).not.toBeNull();
      expect(errorThrown?.message).toBe('DNS A query for example.com timed out after 5000ms');
    }, 7000);
  });

  // --- resolveAAAA tests ---
  describe('resolveAAAA', () => {
    it('should resolve AAAA records successfully', async () => {
      const mockResponse = {
        Status: 0,
        Answer: [{ name: 'example.com', type: 28, TTL: 300, data: '2001:db8::1' }],
      };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
        text: async () => JSON.stringify(mockResponse),
      } as Response);

      const result = await resolveAAAA('example.com');
      expect(result).toEqual(['2001:db8::1']);
      expect(mockFetch).toHaveBeenCalledWith(
        'https://cloudflare-dns.com/dns-query?name=example.com&type=AAAA',
        expect.anything()
      );
    });

     it('should throw an error for AAAA record resolution failure (status not 0)', async () => {
      const mockResponse = { Status: 2 /* SERVFAIL */, Answer: [] };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
        text: async () => JSON.stringify(mockResponse),
      } as Response);

      await expect(resolveAAAA('example.com')).rejects.toThrow('DNS AAAA query failed for example.com');
    });

    it('should throw an error on AAAA record resolution timeout', async () => {
      const mockSuccessfulResponse = { Status: 0, Answer: [{ name: 'example.com', type: 28, TTL: 300, data: '2001:db8::1' }] };
      mockFetch.mockImplementationOnce(createAbortableMockFetch(mockSuccessfulResponse, 200, Infinity));

      const promise = resolveAAAA('example.com');
      vi.advanceTimersByTime(5001);
      await vi.runAllTimersAsync(); // Ensure all timers and microtasks are processed

      let errorThrown: Error | null = null;
      try {
        await promise;
      } catch (e: any) {
        errorThrown = e;
      }
      expect(errorThrown).not.toBeNull();
      expect(errorThrown?.message).toBe('DNS AAAA query for example.com timed out after 5000ms');
    }, 7000);
  });

  // --- resolveMx tests ---
  describe('resolveMx', () => {
    it('should resolve MX records successfully and sort them', async () => {
      const mockResponse = {
        Status: 0,
        Answer: [
          { name: 'example.com', type: 15, TTL: 300, data: '20 alt2.aspmx.l.google.com.' },
          { name: 'example.com', type: 15, TTL: 300, data: '10 aspmx.l.google.com.' },
        ],
      };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
        text: async () => JSON.stringify(mockResponse),
      } as Response);

      const result = await resolveMx('example.com');
      expect(result).toEqual([
        { priority: 10, exchange: 'aspmx.l.google.com' },
        { priority: 20, exchange: 'alt2.aspmx.l.google.com' },
      ]);
    });

    it('should return empty array for MX resolution failure (status not 0)', async () => {
      const mockResponse = { Status: 2, Answer: [] }; // SERVFAIL
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
        text: async () => JSON.stringify(mockResponse),
      } as Response);
      const result = await resolveMx('example.com');
      expect(result).toEqual([]);
    });

    it('should return empty array on MX record resolution timeout', async () => {
      // For MX, timeout should result in an empty array and a warning, not a thrown error that bubbles up.
      const mockSuccessfulResponse = { Status: 0, Answer: [{ name: 'example.com', type: 15, TTL: 300, data: '10 mail.example.com.' }] }; // Data not used due to timeout
      mockFetch.mockImplementationOnce(createAbortableMockFetch(mockSuccessfulResponse, 200, Infinity));
      const consoleWarnSpy = vi.spyOn(console, 'warn');

      const promise = resolveMx('example.com');
      vi.advanceTimersByTime(5001);
      await vi.runAllTimersAsync(); // Ensure all timers and microtasks are processed
      const result = await promise;

      expect(result).toEqual([]);
      expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('Returning empty MX records for example.com due to error: DNS query timed out after 5000ms'));
      consoleWarnSpy.mockRestore();
    }, 7000);
  });

  // --- resolveCname tests ---
  describe('resolveCname', () => {
    it('should resolve CNAME records successfully', async () => {
      const mockResponse = {
        Status: 0,
        Answer: [{ name: 'www.example.com', type: 5, TTL: 300, data: 'example.com.' }],
      };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
        text: async () => JSON.stringify(mockResponse),
      } as Response);

      const result = await resolveCname('www.example.com');
      expect(result).toEqual(['example.com']);
    });

    it('should return empty array for CNAME resolution failure (network error)', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Network error'));
      const result = await resolveCname('example.com');
      expect(result).toEqual([]);
    });

    it('should return empty array on CNAME record resolution timeout', async () => {
      // For CNAME, timeout should result in an empty array and a warning.
      const mockSuccessfulResponse = { Status: 0, Answer: [{ name: 'example.com', type: 5, TTL: 300, data: 'target.example.com.' }] }; // Data not used
      mockFetch.mockImplementationOnce(createAbortableMockFetch(mockSuccessfulResponse, 200, Infinity));
      const consoleWarnSpy = vi.spyOn(console, 'warn');

      const promise = resolveCname('example.com');
      vi.advanceTimersByTime(5001);
      await vi.runAllTimersAsync(); // Ensure all timers and microtasks are processed
      const result = await promise;

      expect(result).toEqual([]);
      expect(consoleWarnSpy).toHaveBeenCalledWith(expect.stringContaining('Returning empty CNAME records for example.com due to error: DNS query timed out after 5000ms'));
      consoleWarnSpy.mockRestore();
    }, 7000);
  });

  // --- resolveTxt tests ---
  describe('resolveTxt', () => {
    it('should resolve TXT records successfully', async () => {
      const mockResponse = {
        Status: 0,
        Answer: [
          { name: 'example.com', type: 16, TTL: 300, data: '"v=spf1 -all"' },
          { name: 'example.com', type: 16, TTL: 300, data: '"another record" "concatenated"' },
        ],
      };
      mockFetch.mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
        text: async () => JSON.stringify(mockResponse),
      } as Response);

      const result = await resolveTxt('example.com');
      expect(result).toEqual([['v=spf1 -all'], ['another record', 'concatenated']]);
    });

    it('should throw an error for TXT resolution failure (non-200 response)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        json: async () => ({}), // Empty json response for error
        text: async () => 'Server Error',
      } as Response);
      await expect(resolveTxt('example.com')).rejects.toThrow('DNS query failed with status 500: Server Error');
    });

    it('should throw an error on TXT record resolution timeout', async () => {
      const mockSuccessfulResponse = { Status: 0, Answer: [{ name: 'example.com', type: 16, TTL: 300, data: '"text record"' }] }; // Data not used
      mockFetch.mockImplementationOnce(createAbortableMockFetch(mockSuccessfulResponse, 200, Infinity));

      const promise = resolveTxt('example.com');
      vi.advanceTimersByTime(5001);
      await vi.runAllTimersAsync(); // Ensure all timers and microtasks are processed

      let errorThrown: Error | null = null;
      try {
        await promise;
      } catch (e: any) {
        errorThrown = e;
      }
      expect(errorThrown).not.toBeNull();
      // The actual error message from resolveTxt is more specific
      expect(errorThrown?.message).toBe('Failed to resolve TXT records for example.com: DNS query timed out after 5000ms');
    }, 7000);
  });

  // TODO: Add tests for fetch throwing different types of errors
  // TODO: Add tests for malformed DNS responses (e.g., missing 'data' in Answer)
});
