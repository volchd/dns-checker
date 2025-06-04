import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { validateDKIM } from '../src/utils/dkim-validator';
import * as dnsResolver from '../src/utils/dns-resolver';

describe('validateDKIM', () => {
  let resolveTxt: import('vitest').MockInstance<unknown[], unknown>;
  let consoleWarn: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    resolveTxt = vi.spyOn(dnsResolver, 'resolveTxt') as unknown as import('vitest').MockInstance<unknown[], unknown>;
    consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {}) as unknown as import('vitest').MockInstance<unknown[], unknown>;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns error for invalid selector', async () => {
    const result = await validateDKIM('', 'example.com');
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Invalid DKIM selector/);
  });

  it('returns error for invalid domain', async () => {
    const result = await validateDKIM('selector', '');
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/Invalid domain/);
  });

  it('returns error if no DKIM record found', async () => {
    resolveTxt.mockResolvedValue([['not_a_dkim_record']]);
    const result = await validateDKIM('selector', 'example.com');
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/No DKIM record found/);
  });

  it('returns valid and record if DKIM record found', async () => {
    resolveTxt.mockResolvedValue([['v=DKIM1; k=rsa; p=abc123']]);
    const result = await validateDKIM('selector', 'example.com');
    expect(result.valid).toBe(true);
    expect(result.record).toMatch(/^v=DKIM1;/);
  });

  it('returns NXDOMAIN error and warns for status 3', async () => {
    resolveTxt.mockRejectedValue(new Error('DNS query failed with status 3: NXDOMAIN'));
    const result = await validateDKIM('selector', 'example.com');
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/NXDOMAIN/);
    expect(consoleWarn).toHaveBeenCalledWith(
      expect.stringContaining('No DKIM record for selector')
    );
  });

  it('returns DNS error and warns for other errors', async () => {
    resolveTxt.mockRejectedValue(new Error('timeout'));
    const result = await validateDKIM('selector', 'example.com');
    expect(result.valid).toBe(false);
    expect(result.error).toMatch(/timeout/);
    expect(consoleWarn).toHaveBeenCalledWith(
      expect.stringContaining('DNS error for selector')
    );
  });
});
