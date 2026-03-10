<div align="center">
    <br/>
    <p>
        <img width="120" title="Minos Verdict" alt="minos-verdict-logo" src="https://github.com/user-attachments/assets/5f048060-c52c-4da7-958e-034b2959e7b6" />
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
        
        USER1 -->|text / file| EXT
        EXT -->|warns about detection results| USER1
        EXT -.->|forwards when safe or allowed by the user| LLMCHATBOT
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
        API[FastAPI Server<br/><small>/detect endpoint</small>]
        FIREWALL[Multiagent Firewall<br/><small>LangGraph Pipeline</small>]
        API -->|invoke | FIREWALL
        FIREWALL -->|detection result| API
    end
    EXT -->|POST /detect<br/>text or files| API
    PROXY -->|POST /detect<br/>text or files| API
    
    API -->|detection result| EXT
    API -->|detection result| PROXY
    style Browser fill:#e3f2fd,stroke:#1976d2,stroke-width:2px,color:#000
    style SystemWide fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px,color:#000
    style Backend fill:#fff3e0,stroke:#f57c00,stroke-width:2px,color:#000

    linkStyle default stroke:#000,stroke-width:2px
```

## Set up 

### 1. uv
Install [uv](https://docs.astral.sh/uv/#installation) (modern Python package manager):

### 2. Configure package options
- `backend`: Copy `backend/.env.example` to `backend/.env` (server settings).
- `multiagent-firewall`: Copy `multiagent-firewall/.env.example` to `multiagent-firewall/.env` (LLM, OCR, NER settings). Customize detection pipeline via `multiagent-firewall/config/pipeline.json` and detection options via `multiagent-firewall/config/detection.json`.
- `proxy`: Copy `proxy/.env.example` to `proxy/.env` and configure to your liking.
- `extension`: Modify `extension/src/config.js`

### 3. Run backend server
The backend package simplifies the connection between the `proxy` and `extension` modules.

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

The extension will intercept web chatbot interactions (ChatGPT, Gemini...) and provide feedback to the user about policy findings and configured guardrail decisions.

### 4b. Run proxy

Detailed information on how to run the proxy package under `proxy/README.md`

The proxy will act as a middleman between the user and any listed endpoint under `proxy/.env`

## License

MIT license.
