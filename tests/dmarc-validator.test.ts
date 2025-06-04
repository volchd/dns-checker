import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { validateDMARC } from '../src/utils/dmarc-validator';
import * as dnsResolver from '../src/utils/dns-resolver';

describe('validateDMARC', () => {
  let resolveTxt: import('vitest').MockInstance<unknown[], unknown>;

  beforeEach(() => {
    resolveTxt = vi.spyOn(dnsResolver, 'resolveTxt') as unknown as import('vitest').MockInstance<unknown[], unknown>;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns error if no DMARC record found', async () => {
    resolveTxt.mockResolvedValue([['not_a_dmarc_record']]);
    const result = await validateDMARC('example.com');
    expect(result.valid).toBe(false);
    expect(result.error?.message).toMatch(/No DMARC record found/);
  });

  it('returns valid and policy if DMARC record with p=none', async () => {
    resolveTxt.mockResolvedValue([['v=DMARC1; p=none; rua=mailto:abc@example.com']]);
    const result = await validateDMARC('example.com');
    expect(result.valid).toBe(true);
    expect(result.policy).toBe('none');
    expect(result.record).toMatch(/^v=DMARC1;/);
  });

  it('returns valid and policy if DMARC record with p=quarantine', async () => {
    resolveTxt.mockResolvedValue([['v=DMARC1; p=quarantine']]);
    const result = await validateDMARC('example.com');
    expect(result.valid).toBe(true);
    expect(result.policy).toBe('quarantine');
  });

  it('returns valid and policy if DMARC record with p=reject', async () => {
    resolveTxt.mockResolvedValue([['v=DMARC1; p=reject']]);
    const result = await validateDMARC('example.com');
    expect(result.valid).toBe(true);
    expect(result.policy).toBe('reject');
  });

  it('returns error if DMARC record missing p tag', async () => {
    resolveTxt.mockResolvedValue([['v=DMARC1; rua=mailto:abc@example.com']]);
    const result = await validateDMARC('example.com');
    expect(result.valid).toBe(false);
    expect(result.error?.message).toMatch(/Missing required policy/);
  });

  it('returns error if DMARC record has invalid policy', async () => {
    resolveTxt.mockResolvedValue([['v=DMARC1; p=invalid']]);
    const result = await validateDMARC('example.com');
    expect(result.valid).toBe(false);
    expect(result.error?.message).toMatch(/Invalid policy value/);
  });

  it('returns NXDOMAIN error for status 3', async () => {
    resolveTxt.mockRejectedValue(new Error('DNS query failed with status 3: NXDOMAIN'));
    const result = await validateDMARC('example.com');
    expect(result.valid).toBe(false);
    expect(result.error?.message).toMatch(/NXDOMAIN/);
  });

  it('returns DNS error for other errors', async () => {
    resolveTxt.mockRejectedValue(new Error('timeout'));
    const result = await validateDMARC('example.com');
    expect(result.valid).toBe(false);
    expect(result.error?.message).toMatch(/timeout/);
  });
});
