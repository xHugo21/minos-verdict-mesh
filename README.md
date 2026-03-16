<div align="center">
    <br/>
    <p>
        <img width="120" title="Minos Verdict" alt="minos-verdict-logo" src="assets/minos-verdict-logo.png" />
        <h1>Minos Verdict Mesh</h1>
    </p>
    <p width="120">
        Modular architecture to inspect, evaluate, and enforce guardrails in LLM interactions.
    </p>
    <br/>
</div>

## Architecture

```mermaid
flowchart TB
    subgraph Browser["🌐 Browser Usage"]
        USER1[User on Web LLM Chatbot]
        EXT[Extension]
        LLMCHATBOT[LLM Chatbot Website]
        
        USER1 -->|prompt / file| EXT
        EXT -->|warns about detection results| USER1
        EXT -.->|forwards when safe| LLMCHATBOT
    end
    subgraph SystemWide["💻 API Usage"]
        USER2[User on CLI/IDE/App]
        PROXY[Proxy]
        LLMAPI[LLM API Providers]
        
        USER2 -->|LLM API calls| PROXY
        PROXY -->|403 block or allow| USER2
        PROXY -.->|forwards when safe| LLMAPI
    end
    subgraph Backend["🔌 Backend"]
        API[FastAPI Server]
        FIREWALL[Multiagent Firewall]
        API -->|invoke | FIREWALL
        FIREWALL -->|detection result| API
    end
    EXT -->|POST /detect| API
    PROXY -->|POST /detect| API
    
    API -->|detection result| EXT
    API -->|detection result| PROXY
    style Browser fill:#e3f2fd,stroke:#1976d2,stroke-width:2px,color:#000
    style SystemWide fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000
    style Backend fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#000

    linkStyle default stroke:#000,stroke-width:2px
```

## Set up 

### 1. uv
Install [uv](https://docs.astral.sh/uv/#installation)

### 2. Configure package options

| Package | Configuration files |
| --- | --- |
| `backend` | `backend/.env` |
| `proxy` | `proxy/.env` |
| `extension` | `extension/src/config.js` |
| `multiagent-firewall` | `multiagent-firewall/.env`, `multiagent-firewall/config/detection.json` and `multiagent-firewall/config/pipeline.json` |

> [!NOTE]
> All `.env` configuration files must be manually created. An `.env.example` of each is uploaded for reference.

### 3. Run backend server
The backend package simplifies the connection between the sensor and the firewall package.

```bash
cd backend && uv sync && uv run python -m app.main
```

> [!NOTE]
> Alternatively, you can build the `backend` image using the provided Dockerfile:
> ```bash
> docker build -t minos-verdict-mesh .
> docker run -p 8000:8000 --env-file .env minos-verdict-mesh
> ```

### 4a. Load extension
1. Go to chrome://extensions/
2. Toggle on "Developer mode"
3. Click "Load unpacked" → choose path to `minos-verdict-mesh/extension/`

The extension will intercept web chatbot interactions and provide feedback to the user about policy findings and configured guardrail decisions.

### 4b. Run proxy

Detailed information on how to run the proxy package under `proxy/README.md`

The proxy will act as a middleman between the user and any listed endpoint under `proxy/.env`

## License

MIT license.
