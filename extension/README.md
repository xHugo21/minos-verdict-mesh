# Browser Extension for LLM Chat Guardrails

A browser extension that intercepts messages in LLM chat platforms and evaluates them against configured guardrails in real time before submission.

## Supported Platforms

- **ChatGPT** - chatgpt.com
- **Gemini** - gemini.google.com

## Installation

### Prerequisites

The extension requires the backend service to be running:

```bash
cd backend
uv sync
uv run python -m app.main
```

The backend should be accessible at `http://127.0.0.1:8000` (configurable in `src/config.js`).

### Loading the Extension

1. Open Chrome and navigate to `chrome://extensions/`
2. Enable "Developer mode" in the top right
3. Click "Load unpacked"
4. Select the `extension/` directory
5. Navigate to a supported platform (ChatGPT, or Gemini)

## Usage

### Text Inspection

1. Type a message that should trigger one of the configured checks (e.g., "My social security number is 123-45-6789")
2. Click send or press Enter
3. The extension will intercept the message and analyze it
4. A risk panel will appear showing the findings returned by the pipeline
5. Depending on the configured minimum block risk and the findings returned, it will allow, warn, or block the send action.

> [!NOTE]
> The panel gives the option to "Send sanitized" which will replace detected values with redacted values and send them to the chatbot

### File Inspection

1. Upload a file (image, PDF, document) in the chat interface
2. The extension will analyze the file content
3. A risk panel will display the findings extracted from the file

## Adding a New Platform

The extension makes it easy to add support for new LLM chat platforms

- Create Platform Adapter: Create a new file `src/platforms/newplatform.js` that follows the structure of one of the existing ones.
- Update manifest.json: Add both the new platform URL to the `matches` section and script to `js` section.
- Allow endpoint to make requests to the backend in `backend/app/config.py`.

## Testing

Run the unit tests (requires Node.js)

```bash
node --test
```

## License

See LICENSE file in the root of the repository.
