"""
Universal Plain Text Parser with segment extraction and character encoding detection.
"""
import hashlib
import re
import uuid
from typing import List
try:
    import chardet
except ImportError:
    chardet = None
from .base import BaseParser, ExtractedContent
from app.models.schemas import Segment

class TextParser(BaseParser):
    supported_types = ['text/plain']

    def can_parse(self, mime_type: str, filename: str) -> bool:
        return mime_type in self.supported_types or filename.lower().endswith(('.txt', '.log', '.csv', '.tsv'))

    async def parse(self, content: bytes, filename: str = '', mime_type: str = '') -> ExtractedContent:
        extracted = ExtractedContent(
            text='',
            source_type='text'
        )
        extracted.content_hash = hashlib.sha256(content).hexdigest()
        segments: List[Segment] = []

        try:
            encoding = 'utf-8'
            if chardet:
                detected = chardet.detect(content[:8192])
                if detected and detected.get('encoding'):
                    encoding = detected['encoding']

            text = content.decode(encoding, errors='replace')
            # Normalize line endings
            text = text.replace('\r\n', '\n').replace('\r', '\n').strip()
            extracted.text = text

            # Extract URLs
            urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', text)
            extracted.links.extend(urls)

            # Heuristics for embedded code
            if re.search(r'def \w+\(.*\):|function \w+\(.*\)\s*{|class \w+:', text):
                extracted.suspicious_elements.append({
                    "type": "embedded_code",
                    "description": "Potential embedded code found in plain text."
                })

            # Segments: split paragraphs if large, or whole body
            paragraphs = [p.strip() for p in text.split('\n\n') if p.strip()]
            if len(paragraphs) > 1:
                for idx, p in enumerate(paragraphs):
                    segments.append(Segment(
                        id=f"seg-txt-para-{idx+1}-{uuid.uuid4().hex[:6]}",
                        text=p,
                        source_type="text",
                        location=f"text:paragraph:{idx+1}",
                        visibility="visible",
                        trust="UNTRUSTED"
                    ))
            elif text:
                segments.append(Segment(
                    id=f"seg-txt-body-{uuid.uuid4().hex[:6]}",
                    text=text,
                    source_type="text",
                    location="text:body",
                    visibility="visible",
                    trust="UNTRUSTED"
                ))

        except Exception as e:
            extracted.extraction_warnings.append(f"Text parsing error: {str(e)}")

        extracted.segments = segments
        return extracted
