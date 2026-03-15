# Transparent Proxy for LLM API Guardrails

A transparent HTTP/HTTPS proxy built with `mitmproxy` that intercepts LLM API requests and blocks requests that violate configured guardrails before they reach the API providers.

> [!NOTE]
> Proxy only analyses prompt data from the role: 'user'. This avoids having false positives from system prompts included by external apps.

## Configuration

Copy `.env.example` to `.env` and configure its values:

```bash
cp .env.example .env
```

An optional `BACKEND_AUTH_TOKEN` can be configured to authenticate proxy requests to the backend. If provided, the same value must be set in `backend/.env`.

Additionally, an optional `PROXY_AUTH_HTPASSWD_FILE` enables client authentication to the proxy itself using an htpasswd file.

## Usage

### 1. Start the Backend

First, ensure the Minos Verdict backend is running

### 2. Start the Proxy

```bash
uv sync
uv run python -m app.main
```

### 3. Configure Your Environment

Set the proxy environment variables in your shell:

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

If client authentication is enabled, include credentials in the proxy URL:

```bash
export HTTP_PROXY=http://user:pass@127.0.0.1:8080
export HTTPS_PROXY=http://user:pass@127.0.0.1:8080
```

### 4. HTTPS interception

If you have to intercept HTTPS traffic, you will have to add the mitmproxy certificate to trusted ones:

```bash
sudo cp mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

Optionally, if you need to accept npm requests:

```bash
npm config set cafile ~/.mitmproxy/mitmproxy-ca-cert.pem
```

> [!WARNING]
> Remember to remove the cafile afterwards with ```bash npm config delete cafile```

### 5. Use Your LLM API Normally

Now any HTTP (or HTTPS) requests to configured endpoints will be intercepted:

If a guardrail violation is detected, the request will be blocked with a 403 response:

## How It Works

1. **Interception**: mitmproxy intercepts all HTTP/HTTPS requests
2. **Filtering**: Only requests to configured hosts/paths are analyzed
3. **Extraction**: Request payloads are parsed to extract text and images
4. **Evaluation**: Content is sent to the backend for multiagent policy evaluation
5. **Blocking**: If risk level exceeds threshold, request is blocked with 403
6. **Forwarding**: Safe requests are forwarded to the original destination
7. **Headers**: Detection metadata is added to response headers

If the proxy cannot analyze an intercepted request, it follows a fail-closed policy and returns a local `403` error instead of forwarding unchecked content.

## Response Headers

The proxy adds detection metadata to response headers:

- **`X-LLM-Guard-Risk-Level`**: Detected risk level (None, Low, Medium, High)
- **`X-LLM-Guard-Detected-Fields`**: Comma-separated list of detected findings

## Limitations

- **Performance**: Each request incurs latency from backend detection call

## Architecture

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│  Local App   │────────▶│   Proxy      │────────▶│   LLM API    │
│              │         │              │         │              │
└──────────────┘         └──────────────┘         └──────────────┘
                               │  ▲
                               │  |
                               ▼  |
                         ┌────────────────┐
                         │   API          │
                         │   Interacts    │
                         │ with multiagent│
                         └────────────────┘
```

## Manual test via cURL

### Text-Only Request
After enabling the proxy, the following cURL request should return a 403 HTTP response with detection headers:

```bash
curl -v -x http://127.0.0.1:8080 \
  -X POST https://api.githubcopilot.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"messages": [{"role": "user", "content": "My SOCIALSECURITYNUMBER is 123-45-6789"}]}'
```

### Image Request (OpenAI Format)
Test image analysis with a base64-encoded image containing content that should trigger the configured guardrails:

```bash
curl -v -x http://127.0.0.1:8080 \
  -X POST https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "gpt-4-vision-preview",
    "messages": [{
      "role": "user",
      "content": [
        {"type": "text", "text": "What do you see?"},
        {
          "type": "image_url",
          "image_url": {
            "url": "data:image/png;base64,<BASE64_IMAGE_DATA>"
          }
        }
      ]
    }]
  }'
```

Replace `<BASE64_IMAGE_DATA>` with actual base64-encoded image data.

## License

See LICENSE file in the root of the repository.
