declare module 'mailauth' {
  export interface SPFResult {
    valid: boolean;
    record?: string;
    error?: Error;
  }

  export interface DMARCResult {
    valid: boolean;
    policy?: string;
    error?: Error;
  }

  export interface MTASTSResult {
    valid: boolean;
    mode?: string;
    mx?: string[];
    error?: Error;
  }

  export interface DKIMResult {
    valid: boolean;
    selector?: string;
    publicKey?: string;
    error?: Error;
  }

  export interface TLSRPTResult {
    valid: boolean;
    rua?: string[];
    error?: Error;
  }

  export class SPF {
    constructor(options: {
      sender: string;
      ip: string;
      helo: string;
      mta: string;
    });
    query(domain: string): Promise<SPFResult>;
  }

  export class DMARC {
    constructor(options: {
      sender: string;
      ip: string;
      helo: string;
      mta: string;
    });
    verify(record: string): Promise<DMARCResult>;
  }

  export class MTASTS {
    constructor(options: {
      domain: string;
      record: string;
    });
    verify(): Promise<MTASTSResult>;
  }

  export class DKIM {
    constructor(options: {
      headerField: string;
      publicKey: string;
    });
    verify(): Promise<DKIMResult>;
  }

  export class TLSRPT {
    constructor(options: {
      domain: string;
      record: string;
    });
    verify(): Promise<TLSRPTResult>;
  }
}
