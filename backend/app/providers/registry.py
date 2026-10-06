"""
Aegis AI Firewall - Provider Adapter Registry
Maps downstream providers (OpenAI, Anthropic, Gemini, Ollama, LiteLLM, vLLM) to adapters.
"""
from typing import Dict
from .base import BaseProviderAdapter
from .openai_adapter import OpenAIAdapter


class ProviderRegistry:
    def __init__(self):
        self._adapters: Dict[str, BaseProviderAdapter] = {}
        # Register standard adapters
        openai_adapter = OpenAIAdapter()
        self.register("openai", openai_adapter)
        self.register("litellm", openai_adapter)
        self.register("vllm", openai_adapter)
        self.register("ollama", openai_adapter)
        self.register("azure", openai_adapter)
        self.register("custom", openai_adapter)

    def register(self, name: str, adapter: BaseProviderAdapter):
        self._adapters[name.lower()] = adapter

    def get_adapter(self, provider_name: str) -> BaseProviderAdapter:
        name = (provider_name or "openai").lower()
        if name in self._adapters:
            return self._adapters[name]
        return self._adapters["openai"]


provider_registry = ProviderRegistry()
