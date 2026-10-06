import hashlib
import re
from defusedxml import ElementTree as ET
from .base import BaseParser, ExtractedContent

class XMLParser(BaseParser):
    supported_types = ['application/xml', 'text/xml']

    def can_parse(self, mime_type: str, filename: str) -> bool:
        return mime_type in self.supported_types or filename.lower().endswith('.xml')

    async def parse(self, content: bytes, filename: str = '', mime_type: str = '') -> ExtractedContent:
        extracted = ExtractedContent(
            text='',
            source_type='xml'
        )
        extracted.content_hash = hashlib.sha256(content).hexdigest()

        try:
            xml_text = content.decode('utf-8', errors='replace')

            # XXE & Entity Expansion (Billion Laughs) Check
            has_dtd = bool(re.search(r'<!DOCTYPE', xml_text, re.IGNORECASE))
            has_entity = bool(re.search(r'<!ENTITY', xml_text, re.IGNORECASE))
            has_system = bool(re.search(r'\bSYSTEM\b|\bPUBLIC\b', xml_text, re.IGNORECASE))

            if has_dtd or has_entity or has_system:
                extracted.suspicious_elements.append({
                    "type": "xxe_vector",
                    "description": "DTD, ENTITY, or external entity references found. Potential XXE or Entity Expansion bomb."
                })
                extracted.extraction_warnings.append("Security Warning: DTD/ENTITY declarations detected and blocked to prevent XXE/DoS.")
                # Safe fallback: extract text content using regex without invoking entity expansion
                clean_text = re.sub(r'<!DOCTYPE[^>]*>', '', xml_text, flags=re.DOTALL | re.IGNORECASE)
                clean_text = re.sub(r'<!ENTITY[^>]*>', '', clean_text, flags=re.DOTALL | re.IGNORECASE)
                # Strip XML tags to get safe text
                raw_text_parts = re.findall(r'>([^<]+)<', clean_text)
                extracted.text = "\n".join(p.strip() for p in raw_text_parts if p.strip())
                return extracted

            # CDATA check
            if '<![CDATA[' in xml_text:
                extracted.suspicious_elements.append({
                    "type": "cdata",
                    "description": "CDATA sections present."
                })

            # Processing instructions
            if '<?' in xml_text and '?>' in xml_text:
                pi_pattern = re.compile(r'<\?.*?\?>', re.DOTALL)
                pis = pi_pattern.findall(xml_text)
                for pi in pis:
                    if 'xml' not in pi.lower(): # exclude standard <?xml ... ?>
                        extracted.suspicious_elements.append({
                            "type": "processing_instruction",
                            "description": f"Processing instruction found: {pi}"
                        })

            # Safe parse for well-formed XML without DTD/entities
            root = ET.fromstring(content)

            text_parts = []
            MAX_DEPTH = 30

            def traverse(element, depth=0):
                if depth > MAX_DEPTH:
                    return
                if element.text and element.text.strip():
                    text_parts.append(element.text.strip())
                for k, v in element.attrib.items():
                    if v and str(v).strip():
                        text_parts.append(str(v).strip())
                for child in element:
                    traverse(child, depth + 1)

            traverse(root)
            extracted.text = "\n".join(text_parts)

            # Scripts check
            script_pattern = re.compile(r'<script.*?>.*?</script>', re.DOTALL | re.IGNORECASE)
            if script_pattern.search(xml_text):
                extracted.suspicious_elements.append({
                    "type": "embedded_script",
                    "description": "Embedded script tag found in XML."
                })

        except ET.ParseError as e:
            extracted.extraction_warnings.append(f"XML parsing error: {str(e)}")
        except Exception as e:
            extracted.extraction_warnings.append(f"Unexpected error in XML parse: {str(e)}")

        return extracted
