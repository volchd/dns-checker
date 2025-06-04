import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import { customDns } from '../src/utils/custom-dns-export';
import * as dnsResolver from '../src/utils/dns-resolver';

describe('customDns.lookup', () => {
  let resolveA: import('vitest').MockInstance<unknown[], unknown>;
  let resolveAAAA: import('vitest').MockInstance<unknown[], unknown>;
  let consoleWarn: import('vitest').MockInstance<unknown[], unknown>;

  beforeEach(() => {
    resolveA = vi.spyOn(dnsResolver, 'resolveA') as unknown as import('vitest').MockInstance<unknown[], unknown>;
    resolveAAAA = vi.spyOn(dnsResolver, 'resolveAAAA') as unknown as import('vitest').MockInstance<unknown[], unknown>;
    consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {}) as unknown as import('vitest').MockInstance<unknown[], unknown>;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('returns AAAA for family 6', async () => {
    resolveAAAA.mockResolvedValue(['2001:db8::1']);
    const cb = vi.fn();
    await customDns.lookup('example.com', { family: 6 }, cb);
    expect(cb).toHaveBeenCalledWith(null, '2001:db8::1', 6);
  });

  it('errors if no AAAA for family 6', async () => {
    resolveAAAA.mockResolvedValue([]);
    const cb = vi.fn();
    await customDns.lookup('example.com', { family: 6 }, cb);
    expect(cb).toHaveBeenCalledWith(expect.any(Error));
    expect(cb.mock.calls[0][0].message).toMatch(/No AAAA records/);
  });

  it('returns A for family 4', async () => {
    resolveA.mockResolvedValue(['1.2.3.4']);
    const cb = vi.fn();
    await customDns.lookup('example.com', { family: 4 }, cb);
    expect(cb).toHaveBeenCalledWith(null, '1.2.3.4', 4);
  });

  it('errors if no A for family 4', async () => {
    resolveA.mockResolvedValue([]);
    const cb = vi.fn();
    await customDns.lookup('example.com', { family: 4 }, cb);
    expect(cb).toHaveBeenCalledWith(expect.any(Error));
    expect(cb.mock.calls[0][0].message).toMatch(/No A records/);
  });

  it('tries A then AAAA for family 0', async () => {
    resolveA.mockResolvedValue([]);
    resolveAAAA.mockResolvedValue(['2001:db8::2']);
    const cb = vi.fn();
    await customDns.lookup('example.com', { family: 0 }, cb);
    expect(cb).toHaveBeenCalledWith(null, '2001:db8::2', 6);
  });

  it('errors if neither A nor AAAA found for family 0', async () => {
    resolveA.mockResolvedValue([]);
    resolveAAAA.mockResolvedValue([]);
    const cb = vi.fn();
    await customDns.lookup('example.com', { family: 0 }, cb);
    expect(cb).toHaveBeenCalledWith(expect.any(Error));
    expect(cb.mock.calls[0][0].message).toMatch(/Could not resolve/);
  });

  it('tries A then AAAA for family undefined', async () => {
    resolveA.mockResolvedValue([]);
    resolveAAAA.mockResolvedValue(['2001:db8::3']);
    const cb = vi.fn();
    await customDns.lookup('example.com', {}, cb);
    expect(cb).toHaveBeenCalledWith(null, '2001:db8::3', 6);
  });

  it('warns and falls back for all:true', async () => {
    resolveA.mockResolvedValue(['1.2.3.4']);
    const cb = vi.fn();
    await customDns.lookup('example.com', { all: true }, cb);
    expect(consoleWarn).toHaveBeenCalledWith(expect.stringContaining('all:true is not fully implemented'));
    expect(cb).toHaveBeenCalledWith(null, '1.2.3.4', 4);
  });

  it('handles resolver errors (A)', async () => {
    resolveA.mockRejectedValue(new Error('fail'));
    const cb = vi.fn();
    await customDns.lookup('example.com', { family: 4 }, cb);
    expect(cb).toHaveBeenCalledWith(expect.any(Error));
    expect(cb.mock.calls[0][0].message).toMatch(/fail/);
  });

  it('handles resolver errors (AAAA)', async () => {
    resolveAAAA.mockRejectedValue(new Error('fail6'));
    const cb = vi.fn();
    await customDns.lookup('example.com', { family: 6 }, cb);
    expect(cb).toHaveBeenCalledWith(expect.any(Error));
    expect(cb.mock.calls[0][0].message).toMatch(/fail6/);
  });

  it('handles thrown non-Error values', async () => {
    resolveA.mockRejectedValue('string error');
    const cb = vi.fn();
    await customDns.lookup('example.com', { family: 4 }, cb);
    expect(cb).toHaveBeenCalledWith(expect.any(Error));
    expect(cb.mock.calls[0][0].message).toMatch(/Unknown error/);
  });
});
