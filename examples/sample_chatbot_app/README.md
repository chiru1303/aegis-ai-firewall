# XYZ Company support chatbot

A standalone Gradio chatbot that behaves like a company's customer-support assistant. By default it sends messages directly to a local Ollama model. With two optional environment settings, the same chat page sends requests through an OpenAI-compatible inspection service, which can record decisions and forward allowed requests to Ollama. The interface and chat behavior stay the same either way.

## Run on Windows

Make sure Ollama is open, then open PowerShell in this folder:

```powershell
ollama list
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --use-feature=truststore -r requirements.txt
python app.py
```

If there is no model installed, download the default model and start the app again:

```powershell
ollama pull qwen2.5:7b-instruct
python app.py
```

The startup message prints the local chat URL. The app checks port `7860` and automatically tries the next available ports if another copy is already running. It lists local chat models automatically; click **Refresh models** after installing one. It listens on this computer only and does not create a public share link.

## Optional request inspection and audit

No code edits are needed. Configure the model provider in the inspection service, then set its base URL and API key in the same terminal before starting the chatbot. Use the base URL shown in that service's integration settings.

PowerShell:

```powershell
$env:GATEWAY_BASE_URL = "http://localhost:3000/v1"
$env:GATEWAY_API_KEY = "paste-the-integration-key-here"
python app.py
```

Command Prompt:

```bat
set GATEWAY_BASE_URL=http://localhost:3000/v1
set GATEWAY_API_KEY=paste-the-integration-key-here
python app.py
```

When `GATEWAY_BASE_URL` is set, each chat request goes to `/chat/completions` on that service and includes the API key. Allowed prompts are forwarded to its configured provider; blocked prompts are held and receive a normal customer-facing reply. Decisions can then be reviewed in its audit/activity page. Keep the key in the terminal environment; do not paste it into source code or browser-side JavaScript. To return to direct local Ollama, start a new terminal without these two variables.

## Try the demo

Use one of the common-question buttons or ask:

- `How can I reset my password?`
- `What information do you need to help me with an order?`
- `How do I contact customer support?`

Change the fictional company name and assistant behavior in the **Company assistant prompt** field, or update `COMPANY_NAME` and `DEFAULT_SYSTEM_PROMPT` in `app.py`.

## Settings

| Variable | Default | Purpose |
| --- | --- | --- |
| `COMPANY_NAME` | `XYZ Company` | Name shown in the chat page |
| `OLLAMA_BASE_URL` | `http://127.0.0.1:11434` | Local Ollama server |
| `OLLAMA_MODEL` | `qwen2.5:7b-instruct` | Initially selected model |
| `OLLAMA_TIMEOUT_SECONDS` | `180` | Time allowed for a model response |
| `GRADIO_SERVER_PORT` | `7860` | First local port to try; the app searches upward for a free port |
| `GATEWAY_BASE_URL` | unset | Optional inspection service base URL, ending in `/v1` |
| `GATEWAY_API_KEY` | unset | Optional server-side API key; required when `GATEWAY_BASE_URL` is set |

For PowerShell, set a value before launching, for example `$env:COMPANY_NAME = "Contoso Help Desk"`. The selected model must be installed in Ollama and configured in the inspection service when using the optional route. This sample has no tools, email access, or order/account lookup integration.

## Troubleshooting

- **No models are listed:** run `ollama list`, install a chat model if needed, and click **Refresh models**.
- **Ollama is unavailable:** start the Ollama app/service or set `OLLAMA_BASE_URL` to its local server address.
- **Model not found:** choose a model shown by `ollama list` or set `OLLAMA_MODEL` to its exact name.
- **Inspection service rejects the request:** set both gateway environment variables in the same terminal, use the current API key, and verify the provider is configured.
- **No local port is available:** close another copy of the chatbot, or set `GRADIO_SERVER_PORT` to a different starting port. Open the URL printed by the app.
