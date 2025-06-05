export interface SPFValidationResult {
  isValid: boolean;
  record: string | null;
  errors: string[];
  warnings: string[];
  dnsLookupCount: number;
  includes: Array<{
    domain: string;
    result: SPFValidationResult;
  }>;
  redirects: Array<{
    domain: string;
    result: SPFValidationResult;
  }>;
  allMechanisms: string[];
}

export interface SPFRecord {
  raw: string;
  version: string;
  mechanisms: {
    all: string | null;
    ip4: string[];
    ip6: string[];
    a: string[];
    mx: string[];
    include: string[]; // Domain strings from the SPF record
    exists: string[];
    redirect: string | null; // Domain string from the SPF record
    exp: string | null;
  };
  modifiers: Record<string, string>;
}
