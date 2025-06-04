interface DnsAnswer {
  data: string;
  type: number;
  name: string;
  TTL: number;
}

interface DnsResponse {
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean;
  CD: boolean;
  Question: Array<{ name: string; type: number }>;
  Answer?: DnsAnswer[];
  Authority?: DnsAnswer[];
  Comment?: string;
}

// Helper function to add timeout to fetch requests
async function fetchWithTimeout(url: string, options: RequestInit = {}, timeout = 5000): Promise<Response> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    return response;
  } catch (error: unknown) {
    clearTimeout(timeoutId);
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        throw new Error(`DNS query timed out after ${timeout}ms`);
      }
    }
    throw error;
  }
}

// Maximum length for a domain name (253 characters per RFC 1035)
const MAX_DOMAIN_LENGTH = 253;

export async function resolveTxt(hostname: string): Promise<string[][]> {
  // Validate hostname before attempting resolution
  if (!hostname || typeof hostname !== 'string' || hostname.length > MAX_DOMAIN_LENGTH) {
    throw new Error(`Invalid hostname: ${hostname}`);
  }
  
  console.log(`[DNS] Resolving TXT records for: ${hostname}`);
  const startTime = Date.now();
  
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=TXT`;
    
    // Additional validation for the URL length (some DNS servers have limits)
    if (url.length > 2048) {
      throw new Error(`DNS query URL too long (${url.length} characters)`);
    }
    
    const response = await fetchWithTimeout(
      url,
      { 
        headers: { 
          'Accept': 'application/dns-json',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache',
          'User-Agent': 'mailauth-dns-checker/1.0'
        },
        // Add some additional fetch options for better reliability
        redirect: 'follow',
        referrerPolicy: 'no-referrer',
        // Add a timeout to the fetch request as well as a secondary protection
      },
      5000 // 10 second timeout (primary timeout)
    );
    
    if (!response.ok) {
      const errorText = await response.text().catch(() => 'No error details');
      throw new Error(`DNS query failed with status ${response.status}: ${errorText}`);
    }
    
    let data: DnsResponse;
    try {
      const responseData = await response.json();
      // Type guard to ensure the response matches our expected DnsResponse structure
      if (!responseData || typeof responseData !== 'object') {
        throw new Error('Invalid DNS response format');
      }
      data = responseData as DnsResponse;
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to parse DNS response: ${errorMessage}`);
    }
    const duration = Date.now() - startTime;
    
    if (data.Status !== 0) {
      if (data.Status === 3) {
        // NXDOMAIN: log as warning, no stack trace
        console.warn(`[DNS] Warning: No TXT records found for ${hostname} (NXDOMAIN, status 3, ${duration}ms)`);
      } else {
        console.error(`[DNS] TXT query failed for ${hostname} (${duration}ms): Status ${data.Status}`);
      }
      throw new Error(`DNS query failed with status ${data.Status}`);
    }
    
    const answers = data.Answer?.map(a => {
      try {
        if (!a.data) return [];
        // Remove surrounding quotes from TXT record data
        const content = String(a.data).replace(/^"/g, '').replace(/"$/g, '');
        // Split long TXT records that are concatenated (if any)
        return content.split('" "').map(part => {
          // Additional validation for each part
          const trimmed = part.trim();
          // Skip parts that are too long (unlikely to be valid)
          return trimmed.length <= 255 ? trimmed : '';
        }).filter(Boolean); // Remove any empty strings
      } catch (error) {
        console.warn(`Error processing TXT record:`, error);
        return [];
      }
    }).filter(arr => arr.length > 0) || []; // Remove any empty arrays
    
    console.log(`[DNS] Resolved ${answers.length} TXT records for ${hostname} (${duration}ms)`);
    return answers;
    
  } catch (error: unknown) {
    const duration = Date.now() - startTime;
    let errorMessage = 'Unknown error during DNS resolution';
    
    if (error instanceof Error) {
      if (error.message.includes('status 3')) {
        // NXDOMAIN
        console.warn(`[DNS] Warning: No TXT records found for ${hostname} (NXDOMAIN, status 3, ${duration}ms)`);
      } else {
        // Other errors: log as error, no stack trace
        console.error(`[DNS] TXT resolution failed for ${hostname} (${duration}ms): ${error.message}`);
      }
      errorMessage = error.message;
    } else if (typeof error === 'string') {
      if (error.includes('status 3')) {
        console.warn(`[DNS] Warning: No TXT records found for ${hostname} (NXDOMAIN, status 3, ${duration}ms)`);
      } else {
        console.error(`[DNS] TXT resolution failed for ${hostname} (${duration}ms): ${error}`);
      }
      errorMessage = error;
    } else {
      console.error(`[DNS] TXT resolution failed for ${hostname} (${duration}ms)`);
    }
    
    throw new Error(`Failed to resolve TXT records for ${hostname}: ${errorMessage}`);
  }
}

export async function resolveMx(hostname: string): Promise<Array<{ exchange: string; priority: number }>> {
  // Validate hostname
  if (!hostname || typeof hostname !== 'string' || hostname.length > MAX_DOMAIN_LENGTH) {
    console.error(`[DNS] Invalid hostname for MX query: ${hostname}`);
    return []; // Return empty as per original design for non-critical errors
  }

  console.log(`[DNS] Resolving MX records for: ${hostname}`);
  const startTime = Date.now();
  
  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=MX`;
    if (url.length > 2048) {
      console.error(`[DNS] MX query URL too long for ${hostname} (${url.length} characters)`);
      return [];
    }

    const response = await fetchWithTimeout(
      url,
      {
        headers: {
          'Accept': 'application/dns-json',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache',
          'User-Agent': 'mailauth-dns-checker/1.0'
        },
        redirect: 'follow',
        referrerPolicy: 'no-referrer',
      },
      5000 // Primary timeout for fetchWithTimeout
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'No error details');
      console.error(`[DNS] MX query failed for ${hostname} with status ${response.status}: ${errorText}`);
      return [];
    }

    let data: DnsResponse;
    try {
      const responseData = await response.json();
      if (!responseData || typeof responseData !== 'object') {
        throw new Error('Invalid DNS response format for MX query');
      }
      data = responseData as DnsResponse;
    } catch (error) {
      const parseErrorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error(`[DNS] Failed to parse MX DNS response for ${hostname}: ${parseErrorMessage}`);
      return [];
    }
    const duration = Date.now() - startTime;

    if (data.Status !== 0) {
      if (data.Status === 3) { // NXDOMAIN
        console.warn(`[DNS] Warning: No MX records found for ${hostname} (NXDOMAIN, status 3, ${duration}ms)`);
      } else {
        console.error(`[DNS] MX query failed for ${hostname} (${duration}ms): Status ${data.Status}, Comment: ${data.Comment || 'N/A'}`);
      }
      return []; // Return empty on query failure as per original design
    }

    const answers = data.Answer?.map(a => {
      const [priorityStr, ...exchangeParts] = a.data.split(' ');
      const priority = parseInt(priorityStr, 10);
      const exchange = exchangeParts.join(' ').toLowerCase().replace(/\.$/, ''); // Handle spaces in exchange, remove trailing dot
      if (isNaN(priority) || !exchange) {
        console.warn(`[DNS] Malformed MX record data for ${hostname}: ${a.data}`);
        return null;
      }
      return { priority, exchange };
    }).filter(Boolean) as Array<{ exchange: string; priority: number }>; // Filter out nulls and assert type
    
    const sortedAnswers = answers.sort((a, b) => a.priority - b.priority);
    console.log(`[DNS] Resolved ${sortedAnswers.length} MX records for ${hostname} (${duration}ms)`);
    return sortedAnswers;

  } catch (error: unknown) {
    const duration = Date.now() - startTime;
    let errorMessage = 'Unknown error during MX resolution';
    if (error instanceof Error) {
      errorMessage = error.message;
      if (error.name === 'AbortError' || error.message.includes('timed out')) {
        console.error(`[DNS] MX resolution timed out for ${hostname} (${duration}ms)`);
      } else {
        console.error(`[DNS] MX resolution failed for ${hostname} (${duration}ms): ${errorMessage}`);
      }
    } else if (typeof error === 'string') {
      errorMessage = error;
      console.error(`[DNS] MX resolution failed for ${hostname} (${duration}ms): ${errorMessage}`);
    } else {
      console.error(`[DNS] MX resolution failed for ${hostname} with unknown error type (${duration}ms)`);
    }
    // Return empty array as this is a non-critical operation
    console.warn(`[DNS] Returning empty MX records for ${hostname} due to error: ${errorMessage}`);
    return [];
  }
}

export async function resolveCname(hostname: string): Promise<string[]> {
  // Validate hostname
  if (!hostname || typeof hostname !== 'string' || hostname.length > MAX_DOMAIN_LENGTH) {
    console.error(`[DNS] Invalid hostname for CNAME query: ${hostname}`);
    return []; // Return empty as per original design for non-critical errors
  }

  console.log(`[DNS] Resolving CNAME records for: ${hostname}`);
  const startTime = Date.now();

  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=CNAME`;
    if (url.length > 2048) {
      console.error(`[DNS] CNAME query URL too long for ${hostname} (${url.length} characters)`);
      return [];
    }

    const response = await fetchWithTimeout(
      url,
      {
        headers: {
          'Accept': 'application/dns-json',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache',
          'User-Agent': 'mailauth-dns-checker/1.0'
        },
        redirect: 'follow',
        referrerPolicy: 'no-referrer',
      },
      5000 // Primary timeout for fetchWithTimeout
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'No error details');
      console.error(`[DNS] CNAME query failed for ${hostname} with status ${response.status}: ${errorText}`);
      return [];
    }

    let data: DnsResponse;
    try {
      const responseData = await response.json();
      if (!responseData || typeof responseData !== 'object') {
        throw new Error('Invalid DNS response format for CNAME query');
      }
      data = responseData as DnsResponse;
    } catch (error) {
      const parseErrorMessage = error instanceof Error ? error.message : 'Unknown error';
      console.error(`[DNS] Failed to parse CNAME DNS response for ${hostname}: ${parseErrorMessage}`);
      return [];
    }
    const duration = Date.now() - startTime;

    if (data.Status !== 0) {
      if (data.Status === 3) { // NXDOMAIN
        console.warn(`[DNS] Warning: No CNAME records found for ${hostname} (NXDOMAIN, status 3, ${duration}ms)`);
      } else {
        console.error(`[DNS] CNAME query failed for ${hostname} (${duration}ms): Status ${data.Status}, Comment: ${data.Comment || 'N/A'}`);
      }
      return []; // Return empty on query failure as per original design
    }

    const answers = data.Answer?.map(a => a.data.toLowerCase().replace(/\.$/, '')) || [];
    console.log(`[DNS] Resolved ${answers.length} CNAME records for ${hostname} (${duration}ms)`);
    return answers;

  } catch (error: unknown) {
    const duration = Date.now() - startTime;
    let errorMessage = 'Unknown error during CNAME resolution';
    if (error instanceof Error) {
      errorMessage = error.message;
      if (error.name === 'AbortError' || error.message.includes('timed out')) {
        console.error(`[DNS] CNAME resolution timed out for ${hostname} (${duration}ms)`);
      } else {
        console.error(`[DNS] CNAME resolution failed for ${hostname} (${duration}ms): ${errorMessage}`);
      }
    } else if (typeof error === 'string') {
      errorMessage = error;
      console.error(`[DNS] CNAME resolution failed for ${hostname} (${duration}ms): ${errorMessage}`);
    } else {
      console.error(`[DNS] CNAME resolution failed for ${hostname} with unknown error type (${duration}ms)`);
    }
    // Return empty array as this is a non-critical operation
    console.warn(`[DNS] Returning empty CNAME records for ${hostname} due to error: ${errorMessage}`);
    return [];
  }
}

export async function resolveA(hostname: string): Promise<string[]> {
  // Validate hostname
  if (!hostname || typeof hostname !== 'string' || hostname.length > MAX_DOMAIN_LENGTH) {
    throw new Error(`Invalid hostname for A query: ${hostname}`);
  }

  console.log(`[DNS] Resolving A records for: ${hostname}`);
  const startTime = Date.now();

  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`;
    if (url.length > 2048) {
      throw new Error(`DNS A query URL too long for ${hostname} (${url.length} characters)`);
    }

    const response = await fetchWithTimeout(
      url,
      {
        headers: {
          'Accept': 'application/dns-json',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache',
          'User-Agent': 'mailauth-dns-checker/1.0'
        },
        redirect: 'follow',
        referrerPolicy: 'no-referrer',
      },
      5000
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'No error details');
      throw new Error(`DNS A query failed for ${hostname} with status ${response.status}: ${errorText}`);
    }

    let data: DnsResponse;
    try {
      const responseData = await response.json();
      if (!responseData || typeof responseData !== 'object') {
        throw new Error('Invalid DNS response format for A query');
      }
      data = responseData as DnsResponse;
    } catch (error) {
      const parseErrorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to parse DNS A response for ${hostname}: ${parseErrorMessage}`);
    }
    const duration = Date.now() - startTime;

    if (data.Status !== 0) {
      if (data.Status === 3) { // NXDOMAIN
        console.warn(`[DNS] Warning: No A records found for ${hostname} (NXDOMAIN, status 3, ${duration}ms)`);
        throw new Error(`DNS A query for ${hostname} resulted in NXDOMAIN (status 3)`);
      } else {
        throw new Error(`DNS A query failed for ${hostname} (${duration}ms): Status ${data.Status}, Comment: ${data.Comment || 'N/A'}`);
      }
    }

    const answers = data.Answer?.filter(a => a.type === 1).map(a => a.data) || []; // type 1 for A records
    console.log(`[DNS] Resolved ${answers.length} A records for ${hostname} (${duration}ms)`);
    return answers;

  } catch (error: unknown) {
    const duration = Date.now() - startTime;
    let errorMessage = `Failed to resolve A records for ${hostname}`;
    if (error instanceof Error) {
      errorMessage = error.message;
      if (error.name === 'AbortError' || error.message.includes('timed out')) {
        console.error(`[DNS] A resolution timed out for ${hostname} (${duration}ms)`);
      } else {
        console.error(`[DNS] A resolution failed for ${hostname} (${duration}ms): ${errorMessage}`);
      }
    } else if (typeof error === 'string') {
      errorMessage = error;
      console.error(`[DNS] A resolution failed for ${hostname} (${duration}ms): ${errorMessage}`);
    } else {
      console.error(`[DNS] A resolution failed for ${hostname} with unknown error type (${duration}ms)`);
    }
    // Construct specific timeout message
    if (errorMessage.includes('timed out')) {
      throw new Error(`DNS A query for ${hostname} ${errorMessage.substring('DNS query '.length)}`);
    } else {
      throw new Error(errorMessage);
    }
  }
}

export async function resolveAAAA(hostname: string): Promise<string[]> {
  // Validate hostname
  if (!hostname || typeof hostname !== 'string' || hostname.length > MAX_DOMAIN_LENGTH) {
    throw new Error(`Invalid hostname for AAAA query: ${hostname}`);
  }

  console.log(`[DNS] Resolving AAAA records for: ${hostname}`);
  const startTime = Date.now();

  try {
    const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=AAAA`;
    if (url.length > 2048) {
      throw new Error(`DNS AAAA query URL too long for ${hostname} (${url.length} characters)`);
    }

    const response = await fetchWithTimeout(
      url,
      {
        headers: {
          'Accept': 'application/dns-json',
          'Cache-Control': 'no-cache',
          'Pragma': 'no-cache',
          'User-Agent': 'mailauth-dns-checker/1.0'
        },
        redirect: 'follow',
        referrerPolicy: 'no-referrer',
      },
      5000
    );

    if (!response.ok) {
      const errorText = await response.text().catch(() => 'No error details');
      throw new Error(`DNS AAAA query failed for ${hostname} with status ${response.status}: ${errorText}`);
    }

    let data: DnsResponse;
    try {
      const responseData = await response.json();
      if (!responseData || typeof responseData !== 'object') {
        throw new Error('Invalid DNS response format for AAAA query');
      }
      data = responseData as DnsResponse;
    } catch (error) {
      const parseErrorMessage = error instanceof Error ? error.message : 'Unknown error';
      throw new Error(`Failed to parse DNS AAAA response for ${hostname}: ${parseErrorMessage}`);
    }
    const duration = Date.now() - startTime;

    if (data.Status !== 0) {
      if (data.Status === 3) { // NXDOMAIN
        console.warn(`[DNS] Warning: No AAAA records found for ${hostname} (NXDOMAIN, status 3, ${duration}ms)`);
        throw new Error(`DNS AAAA query for ${hostname} resulted in NXDOMAIN (status 3)`);
      } else {
        throw new Error(`DNS AAAA query failed for ${hostname} (${duration}ms): Status ${data.Status}, Comment: ${data.Comment || 'N/A'}`);
      }
    }

    const answers = data.Answer?.filter(a => a.type === 28).map(a => a.data) || []; // type 28 for AAAA records
    console.log(`[DNS] Resolved ${answers.length} AAAA records for ${hostname} (${duration}ms)`);
    return answers;

  } catch (error: unknown) {
    const duration = Date.now() - startTime;
    let errorMessage = `Failed to resolve AAAA records for ${hostname}`;
    if (error instanceof Error) {
      errorMessage = error.message;
      if (error.name === 'AbortError' || error.message.includes('timed out')) {
        console.error(`[DNS] AAAA resolution timed out for ${hostname} (${duration}ms)`);
      } else {
        console.error(`[DNS] AAAA resolution failed for ${hostname} (${duration}ms): ${errorMessage}`);
      }
    } else if (typeof error === 'string') {
      errorMessage = error;
      console.error(`[DNS] AAAA resolution failed for ${hostname} (${duration}ms): ${errorMessage}`);
    } else {
      console.error(`[DNS] AAAA resolution failed for ${hostname} with unknown error type (${duration}ms)`);
    }
    // Construct specific timeout message
    if (errorMessage.includes('timed out')) {
      throw new Error(`DNS AAAA query for ${hostname} ${errorMessage.substring('DNS query '.length)}`);
    } else {
      throw new Error(errorMessage);
    }
  }
}
