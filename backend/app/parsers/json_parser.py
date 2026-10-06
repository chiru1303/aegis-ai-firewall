"""
Universal JSON Parser with recursive JSON-path traversal and segment extraction.
Extracts every string value and key into typed Segments with exact JSONPath locations (e.g. $.data.users[0].query).
"""
import hashlib
import json
import re
import uuid
from typing import Any, List, Dict
from .base import BaseParser, ExtractedContent
from app.models.schemas import Segment

class JSONParser(BaseParser):
    supported_types = ['application/json']
    MAX_DEPTH = 25
    MAX_SIZE = 10 * 1024 * 1024 # 10MB

    def can_parse(self, mime_type: str, filename: str) -> bool:
        return mime_type in self.supported_types or filename.lower().endswith('.json')

    async def parse(self, content: bytes, filename: str = '', mime_type: str = '') -> ExtractedContent:
        extracted = ExtractedContent(
            text='',
            source_type='api'
        )
        extracted.content_hash = hashlib.sha256(content).hexdigest()
        segments: List[Segment] = []

        if len(content) > self.MAX_SIZE:
            extracted.extraction_warnings.append("JSON exceeds max size. Skipping parse.")
            return extracted

        try:
            data = json.loads(content.decode('utf-8', errors='replace'))
            string_values = []
            suspicious_keys = {'system', 'instruction', 'prompt', 'command', 'eval', 'exec', 'override', 'jailbreak'}
            url_pattern = re.compile(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')

            def traverse(obj: Any, path: str, depth: int):
                if depth > self.MAX_DEPTH:
                    extracted.extraction_warnings.append(f"JSON max depth ({self.MAX_DEPTH}) exceeded at {path}.")
                    return

                if isinstance(obj, dict):
                    for k, v in obj.items():
                        child_path = f"{path}.{k}"
                        # Check key name
                        if k.lower() in suspicious_keys:
                            extracted.suspicious_elements.append({
                                "type": "suspicious_key",
                                "path": child_path,
                                "description": f"Suspicious key found: {k}"
                            })
                            segments.append(Segment(
                                id=f"seg-json-key-{uuid.uuid4().hex[:6]}",
                                text=k,
                                source_type="api",
                                location=f"json:{child_path}:key",
                                visibility="metadata",
                                trust="EXTERNAL"
                            ))
                        traverse(v, child_path, depth + 1)

                elif isinstance(obj, list):
                    for idx, item in enumerate(obj):
                        child_path = f"{path}[{idx}]"
                        traverse(item, child_path, depth + 1)

                elif isinstance(obj, str):
                    val_clean = obj.strip()
                    if val_clean:
                        string_values.append(val_clean)
                        segments.append(Segment(
                            id=f"seg-json-val-{uuid.uuid4().hex[:6]}",
                            text=val_clean,
                            source_type="api",
                            location=f"json:{path}",
                            visibility="visible",
                            trust="EXTERNAL"
                        ))

                        urls = url_pattern.findall(val_clean)
                        extracted.links.extend(urls)

                        # Detect potential base64 in value
                        if len(val_clean) >= 40 and len(val_clean) % 4 == 0 and re.match(r'^[A-Za-z0-9+/=]+$', val_clean):
                            extracted.suspicious_elements.append({
                                "type": "encoded_content",
                                "path": path,
                                "description": "Potential base64 encoded content in JSON value."
                            })

                elif isinstance(obj, (int, float, bool)):
                    # Scalar metadata
                    pass

            traverse(data, "$", 0)
            extracted.text = "\n".join(string_values)

        except json.JSONDecodeError as e:
            extracted.extraction_warnings.append(f"JSON parsing error: {str(e)}")
        except Exception as e:
            extracted.extraction_warnings.append(f"Unexpected error in JSON parse: {str(e)}")

        extracted.segments = segments
        return extracted
