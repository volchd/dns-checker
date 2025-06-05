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

3. Configure environment variables:
   ```bash
   cp .env.example .env
   ```
   Edit `.env` file with your settings if needed.

4. Authenticate with Cloudflare:
   ```bash
   npx wrangler login
   ```

5. Start the development server:
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
  "timestamp": "2024-01-15T10:30:00.000Z",
  "score": {
    "total": 65,
    "max": 100,
    "grade": "C",
    "summary": "Basic email security configured but improvements needed"
  },
  "checks": {
    "spf": {
      "valid": true,
      "record": "v=spf1 ip4:192.0.2.0/24 include:_spf.google.com -all",
      "policy": "hard fail",
      "includes": ["_spf.google.com"],
      "mechanisms": ["ip4:192.0.2.0/24", "include:_spf.google.com", "-all"],
      "score": {
        "value": 25,
        "max": 25,
        "details": ["Hard fail policy (+15)", "No ip4:any or +all (+10)"]
      }
    },
    "dmarc": {
      "valid": false,
      "record": null,
      "error": "No DMARC record found",
      "score": {
        "value": 0,
        "max": 35,
        "details": ["No DMARC record (-35)"]
      }
    },
    "dkim": {
      "valid": null,
      "error": "Selector required",
      "selectors_checked": ["default", "google"],
      "score": {
        "value": 0,
        "max": 20,
        "details": ["DKIM not configured (-20)"]
      }
    },
    "mta_sts": {
      "valid": true,
      "dns_record": "v=STSv1; id=20240115000000Z",
      "policy": {
        "version": "STSv1",
        "mode": "enforce",
        "max_age": 604800,
        "mx": ["*.google.com"]
      },
     "score": {
    "total": 55,
    "spf": 20,
    "dkim": 0,
    "dmarc": 30,
    "details": {
      "spf_exists": 10,
      "spf_syntax": 5,
      "spf_all": 0,
      "spf_no_plusall": 5,
      "dkim_exists": 0,
      "dkim_key_strength": 0,
      "dkim_multiple_selectors_bonus": 0,
      "dmarc_exists": 10,
      "dmarc_policy": 20,
      "dmarc_rua_bonus": 5
    },
    "reasons": {
      "spf": "SPF record does not specify an \"all\" mechanism.",
      "dkim": "DKIM record is missing or invalid.",
      "dmarc": "DMARC reporting (rua) is enabled."
    },
    "recommendations": {
      "spf": "Add an \"all\" mechanism (preferably \"-all\") to define policy for all mail sources.",
      "dkim": "Add a valid DKIM record with at least 1024-bit key and enable key rotation if possible.",
      "dmarc": "No change needed. Reporting is recommended."
    }
  }
    }
  }
}
```

## Deployment

1. Configure your production environment:
   ```bash
   npx wrangler init
   ```

2. Build the project:
   ```bash
   npm run build
   ```

3. Test the build:
   ```bash
   npm run test
   ```

4. Deploy to Cloudflare Workers:
   ```bash
   npx wrangler deploy
   ```

5. The worker will be deployed to `https://<worker-name>.<your-account>.workers.dev`

## Testing

Run the test suite:
```bash
npm run test
```

Run tests in watch mode during development:
```bash
npm run test:watch
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please make sure to update tests as appropriate and follow the existing code style.

## Environment Variables

The following environment variables can be configured:

- `ALLOWED_ORIGINS` - Comma-separated list of allowed CORS origins
- `MAX_REQUESTS_PER_MIN` - Rate limit per IP (default: 60)
- `CACHE_TTL` - DNS cache TTL in seconds (default: 300)

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
