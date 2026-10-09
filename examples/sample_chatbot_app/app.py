"""A small fictional-company support chatbot powered by a local Ollama model."""

from __future__ import annotations

import os
import time
from html import escape
from typing import Any

import gradio as gr
import httpx


OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
COMPANY_NAME = os.getenv("COMPANY_NAME", "XYZ Company").strip() or "XYZ Company"
DEFAULT_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b-instruct")
REQUEST_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "180"))

DEFAULT_SYSTEM_PROMPT = f"""You are the customer support assistant for {COMPANY_NAME}.
Be warm, clear, and concise. Help with general product, order, billing, and account questions.
Do not invent company policies, order details, account status, or actions you cannot perform.
Never ask customers to share passwords or full payment credentials. For private account changes,
explain that the customer should use the official account portal or contact the support team."""

SUGGESTIONS = [
    "How can I reset my password?",
    "What information do you need to help me with an order?",
    "How do I contact customer support?",
]


def get_models() -> tuple[list[str], str]:
    """Discover locally available Ollama chat models."""
    try:
        response = httpx.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=5.0)
        response.raise_for_status()
        models: list[str] = []
        for item in response.json().get("models", []):
            name = item.get("name", "")
            # Hide cloud references and embedding-only models from this local chat UI.
            if not name or ":cloud" in name.lower() or "embed" in name.lower():
                continue
            if int(item.get("size") or 0) < 1_000_000:
                continue
            models.append(name)
        if not models:
            return [], "Ollama is running, but no local chat models were found."
        return models, f"Connected to Ollama · {len(models)} local models available"
    except (httpx.HTTPError, ValueError) as exc:
        return [], f"Ollama is unavailable at {OLLAMA_BASE_URL}: {exc}"


def refresh_models() -> tuple[Any, str]:
    models, status = get_models()
    selected = DEFAULT_MODEL if DEFAULT_MODEL in models else (models[0] if models else None)
    return gr.Dropdown(choices=models, value=selected, interactive=bool(models)), status


def _messages(message: str, history: list[dict[str, Any]], system_prompt: str) -> list[dict[str, str]]:
    result = [{"role": "system", "content": system_prompt.strip()}] if system_prompt.strip() else []
    for item in history or []:
        role, content = item.get("role"), item.get("content")
        if role in {"user", "assistant"} and isinstance(content, str) and content.strip():
            result.append({"role": role, "content": content})
    result.append({"role": "user", "content": message.strip()})
    return result


def chat(message: str, history: list[dict[str, Any]], model: str, system_prompt: str):
    if not message or not message.strip():
        return list(history or []), "Type a message to start the conversation."
    if not model:
        return list(history or []), "Select a local Ollama model first."

    started = time.perf_counter()
    try:
        response = httpx.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json={
                "model": model,
                "messages": _messages(message, history, system_prompt or ""),
                "stream": False,
            },
            timeout=REQUEST_TIMEOUT,
            trust_env=False,
        )
        response.raise_for_status()
        answer = response.json().get("message", {}).get("content", "I couldn't generate a reply. Please try again.")
        elapsed = round((time.perf_counter() - started) * 1000)
        status = f"{COMPANY_NAME} assistant · {model} · {elapsed} ms"
    except httpx.TimeoutException:
        answer = "The local model took too long to respond. Try a smaller model or increase OLLAMA_TIMEOUT_SECONDS."
        status = "Response timed out"
    except httpx.HTTPStatusError as exc:
        answer = f"Ollama returned HTTP {exc.response.status_code}. Check that the selected model is installed."
        status = f"Request failed · HTTP {exc.response.status_code}"
    except (httpx.HTTPError, ValueError, TypeError, KeyError) as exc:
        answer = f"I couldn't reach the local model. Check that Ollama is running at {OLLAMA_BASE_URL}."
        status = f"Connection issue · {type(exc).__name__}"

    updated = list(history or [])
    updated.extend([
        {"role": "user", "content": message.strip()},
        {"role": "assistant", "content": answer},
    ])
    return updated, status


models, initial_status = get_models()
initial_model = DEFAULT_MODEL if DEFAULT_MODEL in models else (models[0] if models else None)
css = """
.gradio-container { max-width: 1050px !important; margin: 0 auto !important; }
#brand { border-radius: 16px; padding: 22px 26px; background: linear-gradient(120deg,#123c66,#237c8b); color: white; }
#brand h1 { margin: 0 0 6px; font-size: 1.75rem; }
#brand p { margin: 0; opacity: .88; }
"""

with gr.Blocks(title=f"{COMPANY_NAME} · Customer Support", theme=gr.themes.Soft(), css=css) as demo:
    gr.HTML(f'<div id="brand"><h1>{escape(COMPANY_NAME)} Support</h1><p>How can we help you today?</p></div>')
    with gr.Row():
        model = gr.Dropdown(
            choices=models,
            value=initial_model,
            label="Local chat model",
            allow_custom_value=True,
            scale=4,
        )
        refresh = gr.Button("Refresh models", scale=1)
    status = gr.Markdown(initial_status)
    with gr.Accordion("Assistant instructions", open=False):
        system_prompt = gr.Textbox(
            value=DEFAULT_SYSTEM_PROMPT,
            label="Company assistant prompt",
            lines=5,
        )
    chatbot = gr.Chatbot(type="messages", height=480, label="Conversation", allow_tags=False)
    with gr.Row():
        prompt = gr.Textbox(placeholder="Write a message…", label="Message", scale=8, lines=2)
        send = gr.Button("Send", variant="primary", scale=1)
        clear = gr.Button("New chat", scale=1)
    gr.Markdown("**Common questions**")
    with gr.Row():
        for example in SUGGESTIONS:
            gr.Button(example, size="sm").click(lambda q=example: q, outputs=prompt)

    send.click(chat, [prompt, chatbot, model, system_prompt], [chatbot, status]).then(lambda: "", outputs=prompt)
    prompt.submit(chat, [prompt, chatbot, model, system_prompt], [chatbot, status]).then(lambda: "", outputs=prompt)
    clear.click(lambda: ([], f"{COMPANY_NAME} assistant · New conversation"), outputs=[chatbot, status])
    refresh.click(refresh_models, outputs=[model, status])


if __name__ == "__main__":
    print(f"Company: {COMPANY_NAME}")
    print(f"Ollama: {OLLAMA_BASE_URL}")
    print("Chat page: http://127.0.0.1:7860")
    demo.launch(
        server_name="127.0.0.1",
        server_port=int(os.getenv("GRADIO_SERVER_PORT", "7860")),
        share=False,
    )
