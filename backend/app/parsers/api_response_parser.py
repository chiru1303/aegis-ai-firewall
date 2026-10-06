import hashlib
import json
import re
from xml.etree import ElementTree as ET
from .base import BaseParser, ExtractedContent

class APIResponseParser(BaseParser):
    supported_types = ['application/json', 'application/xml', 'text/xml']
    # Not meant to be used for general files, but specifically for API interceptions

    def can_parse(self, mime_type: str, filename: str) -> bool:
        # We rely on explicit invocation for API responses, but we'll accept typical API types
        return mime_type in self.supported_types

    async def parse(self, content: bytes, filename: str = '', mime_type: str = '') -> ExtractedContent:
        extracted = ExtractedContent(
            text='',
            source_type='api_response'
        )
        extracted.content_hash = hashlib.sha256(content).hexdigest()

        try:
            # Try JSON first
            is_json = False
            try:
                data = json.loads(content.decode('utf-8', errors='replace'))
                extracted.text = json.dumps(data, indent=2)
                is_json = True
            except json.JSONDecodeError:
                pass

            if not is_json:
                # Try XML
                try:
                    root = ET.fromstring(content)

                    text_parts = []
                    def traverse(element):
                        if element.text and element.text.strip():
                            text_parts.append(element.text.strip())
                        for child in element:
                            traverse(child)
                    traverse(root)
                    extracted.text = "\n".join(text_parts)
                except ET.ParseError:
                    # Fallback to plain text
                    extracted.text = content.decode('utf-8', errors='replace')

            # Check for instructions in data
            instruction_patterns = [r'ignore previous instructions', r'system prompt', r'you must', r'you are an ai']
            for pat in instruction_patterns:
                if re.search(pat, extracted.text, re.IGNORECASE):
                    extracted.suspicious_elements.append({
                        "type": "instruction_in_data",
                        "description": "Instruction-like content found in API response data."
                    })

            # Check for script injections
            if '<script' in extracted.text.lower():
                extracted.suspicious_elements.append({
                    "type": "script_injection",
                    "description": "Script tag detected in API response."
                })

        except Exception as e:
            extracted.extraction_warnings.append(f"API Response parsing error: {str(e)}")

        return extracted
