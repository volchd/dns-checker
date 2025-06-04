import { patchMailAuth } from './mailauth-patch';

// Ensure patchMailAuth runs and customDns is available on globalThis
if (typeof (globalThis as any).dns === "undefined") patchMailAuth();

export const customDns = (globalThis as any).dns;
