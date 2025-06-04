# Email Authentication Checker

A Cloudflare Worker that checks email authentication records (SPF, DKIM, DMARC, MTA-STS, TLS-RPT) for a given domain.

## Features

- Checks SPF, DKIM, and DMARC records (required for email authentication)
- Optionally checks MTA-STS and TLS-RPT records
- Returns results in JSON format
- No authentication required
- Runs entirely on Cloudflare Workers

## Prerequisites

- Node.js (v16 or later)
- npm (v7 or later)
- Cloudflare account
- Wrangler CLI (`npm install -g wrangler`)

## Local Development

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd dns-checker
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Authenticate with Cloudflare:
   ```bash
   npx wrangler login
   ```

4. Start the development server:
   ```bash
   npm run dev
   ```

   This will start the worker locally at `http://localhost:8787`

## Usage

Make a GET request to the worker with a `domain` query parameter:

```
GET /?domain=example.com
```

### Example Response

```json
{
  "domain": "example.com",
  "timestamp": "2024-06-03T12:00:00.000Z",
  "checks": {
    "spf": {
      "valid": true,
      "record": "v=spf1 include:_spf.google.com ~all"
    },
    "dmarc": {
      "valid": true,
      "record": "v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com;",
      "policy": "none"
    },
    "dkim": {
      "valid": true,
      "selector": "google",
      "publicKey": "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA..."
    },
    "mta_sts": {
      "valid": true,
      "record": "v=STSv1; id=20240101",
      "mode": "testing",
      "mx": ["mx1.example.com", "mx2.example.com"]
    },
    "tls_rpt": {
      "valid": true,
      "record": "v=TLSRPTv1; rua=mailto:tls-reports@example.com",
      "rua": ["mailto:tls-reports@example.com"]
    }
  }
}
```

## Deployment

1. Build the project:
   ```bash
   npm run build
   ```

2. Deploy to Cloudflare Workers:
   ```bash
   npx wrangler deploy
   ```

3. The worker will be deployed to `https://<worker-name>.<your-account>.workers.dev`

## Error Handling

The API returns appropriate HTTP status codes:

- `200`: Success
- `400`: Bad request (missing or invalid domain parameter)
- `405`: Method not allowed (only GET and OPTIONS are supported)
- `500`: Internal server error

## CORS

The API supports CORS and can be called from any origin.

## License

MIT
