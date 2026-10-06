# Optional Ollama chatbot example

This standalone Gradio app demonstrates the Aegis OpenAI-compatible gateway with local Ollama. It is not required to run the Aegis dashboard or scan API.

1. Start Aegis with `start.bat` and configure a reachable Ollama provider in **Connect an app**.
2. Reveal the Aegis API key on that page.
3. In a terminal from this directory, install the example dependencies and provide the key:

   ```powershell
   python -m pip install -r requirements.txt
   $env:AEGIS_API_KEY = "paste-the-local-key-here"
   python app.py
   ```

4. Open `http://localhost:7860`.

The example includes a direct-to-Ollama mode that intentionally bypasses the firewall for a local security comparison. Use it only with a local test model and non-sensitive prompts. Do not expose the Gradio app to a network; it binds to all interfaces for the local demo.
