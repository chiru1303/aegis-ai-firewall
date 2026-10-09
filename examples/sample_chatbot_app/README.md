# XYZ Company support chatbot

A standalone Gradio chatbot that behaves like a company's customer-support assistant. It sends messages directly to an Ollama model running on this computer. It does not use a hosted AI service or company database; account-specific questions receive a hand-off suggestion.

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

For PowerShell, set a value before launching, for example `$env:COMPANY_NAME = "Contoso Help Desk"`. The selected model must be installed in Ollama. This sample has no tools, email access, or order/account lookup integration.

## Troubleshooting

- **No models are listed:** run `ollama list`, install a chat model if needed, and click **Refresh models**.
- **Ollama is unavailable:** start the Ollama app/service or set `OLLAMA_BASE_URL` to its local server address.
- **Model not found:** choose a model shown by `ollama list` or set `OLLAMA_MODEL` to its exact name.
- **No local port is available:** close another copy of the chatbot, or set `GRADIO_SERVER_PORT` to a different starting port. Open the URL printed by the app.
