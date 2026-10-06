"""
Universal Email (.eml / .msg) Parser with recursive attachment routing and segment extraction.
Extracts headers, body plain text, HTML parts, quoted-reply chains, and recursively inspects attachments.
"""
import hashlib
import email
import re
import uuid
from email.policy import default
from typing import List, Dict, Any
from .base import BaseParser, ExtractedContent
from app.models.schemas import Segment

class EmailParser(BaseParser):
    supported_types = ['message/rfc822', 'application/vnd.ms-outlook']

    def can_parse(self, mime_type: str, filename: str) -> bool:
        return mime_type in self.supported_types or filename.lower().endswith(('.eml', '.msg'))

    async def parse(self, content: bytes, filename: str = '', mime_type: str = '') -> ExtractedContent:
        extracted = ExtractedContent(
            text='',
            source_type='email'
        )
        extracted.content_hash = hashlib.sha256(content).hexdigest()
        segments: List[Segment] = []

        try:
            if filename.lower().endswith(".msg"):
                extracted.extraction_warnings.append("Binary Outlook MSG requires conversion to EML")
                return extracted
            msg = email.message_from_bytes(content, policy=default)
            if msg.defects:
                extracted.extraction_warnings.append("Malformed email container")

            # 1. Headers
            headers_to_check = ['subject', 'from', 'reply-to', 'to', 'cc']
            for h in headers_to_check:
                val = msg.get(h)
                if val:
                    val_str = str(val).strip()
                    extracted.metadata[h] = val_str
                    segments.append(Segment(
                        id=f"seg-email-hdr-{h}-{uuid.uuid4().hex[:6]}",
                        text=val_str,
                        source_type="email",
                        location=f"email:header:{h}",
                        visibility="metadata",
                        trust="EXTERNAL"
                    ))

            # Spoofing check
            if 'Authentication-Results' in msg:
                auth_res = str(msg['Authentication-Results'])
                if 'fail' in auth_res.lower() or 'none' in auth_res.lower():
                    extracted.suspicious_elements.append({
                        "type": "spoofed_header",
                        "description": "Authentication-Results indicates possible spoofing."
                    })

            body_texts = []
            email_uid = uuid.uuid4().hex[:6]

            # 2. Walk parts
            for index, part in enumerate(msg.walk()):
                if index >= 100:
                    extracted.extraction_warnings.append("Email part budget exceeded")
                    break
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))

                # Attachment detection
                if "attachment" in content_disposition or part.get_filename():
                    att_name = part.get_filename() or f"attachment_{uuid.uuid4().hex[:4]}"
                    extracted.embedded_objects.append(att_name)
                    att_payload = part.get_payload(decode=True)
                    att_parent_id = f"seg-email-att-{att_name}-{email_uid}"

                    segments.append(Segment(
                        id=att_parent_id,
                        text=f"Attachment: {att_name} ({len(att_payload) if att_payload else 0} bytes)",
                        source_type="email",
                        location=f"email:attachment:{att_name}",
                        visibility="metadata",
                        trust="EXTERNAL"
                    ))

                    # Recursive routing of text-based or parseable attachments
                    if att_payload:
                        try:
                            from .registry import registry
                            att_parser = registry.get_parser(content_type, att_name)
                            if att_parser and not isinstance(att_parser, EmailParser):
                                child_extracted = await att_parser.parse(att_payload, att_name, content_type)
                                extracted.extraction_warnings.extend(child_extracted.extraction_warnings)
                                for c_seg in child_extracted.segments:
                                    c_seg.parent_id = att_parent_id
                                    c_seg.trust = "EXTERNAL"
                                    segments.append(c_seg)
                                if child_extracted.text:
                                    body_texts.append(f"[Attachment {att_name}]:\n{child_extracted.text}")
                            else:
                                extracted.extraction_warnings.append("Attachment format requires manual review")
                        except Exception:
                            extracted.extraction_warnings.append("Attachment extraction failed")

                elif content_type == "text/plain":
                    try:
                        part_text = part.get_content()
                        if part_text:
                            # Split quoted-reply chains
                            lines = part_text.splitlines()
                            primary_lines = []
                            quoted_lines = []
                            in_quoted = False

                            for line in lines:
                                if line.strip().startswith('>') or re.match(r'^On\s.+wrote:\s*$', line.strip(), re.I):
                                    in_quoted = True
                                if in_quoted:
                                    quoted_lines.append(line)
                                else:
                                    primary_lines.append(line)

                            primary_text = "\n".join(primary_lines).strip()
                            quoted_text = "\n".join(quoted_lines).strip()

                            if primary_text:
                                body_texts.append(primary_text)
                                segments.append(Segment(
                                    id=f"seg-email-body-{uuid.uuid4().hex[:6]}",
                                    text=primary_text,
                                    source_type="email",
                                    location="email:body:text",
                                    visibility="visible",
                                    trust="EXTERNAL"
                                ))

                            if quoted_text:
                                segments.append(Segment(
                                    id=f"seg-email-quote-{uuid.uuid4().hex[:6]}",
                                    text=quoted_text,
                                    source_type="email",
                                    location="email:quoted_reply",
                                    visibility="visible",
                                    trust="EXTERNAL"
                                ))

                            urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', part_text)
                            extracted.links.extend(urls)
                    except Exception as e:
                        extracted.extraction_warnings.append(f"Failed to read text/plain: {str(e)}")

                elif content_type == "text/html":
                    try:
                        part_html = part.get_content()
                        if part_html:
                            from .html_parser import HTMLParser
                            h_parser = HTMLParser()
                            h_res = await h_parser.parse(part_html.encode('utf-8'), "email_body.html", "text/html")
                            extracted.extraction_warnings.extend(h_res.extraction_warnings)
                            if h_res.metadata.get("image_sources"):
                                extracted.extraction_warnings.append(
                                    "Email HTML references external images that were not OCR-inspected"
                                )
                            for h_seg in h_res.segments:
                                h_seg.source_type = "email"
                                h_seg.trust = "EXTERNAL"
                                h_seg.location = f"email:{h_seg.location}"
                                segments.append(h_seg)
                            if h_res.text and not body_texts:
                                body_texts.append(h_res.text)
                            extracted.links.extend(h_res.links)
                    except Exception as e:
                        extracted.extraction_warnings.append(f"Failed to read text/html: {str(e)}")

            extracted.text = "\n\n".join(body_texts)

            # Phishing / urgency indicators
            urgency_patterns = [r'urgent', r'immediate action required', r'account suspended', r'verify your account', r'reset your password immediately']
            for pattern in urgency_patterns:
                if re.search(pattern, extracted.text, re.IGNORECASE) or re.search(pattern, extracted.metadata.get('subject', ''), re.IGNORECASE):
                    extracted.suspicious_elements.append({
                        "type": "phishing_indicator",
                        "description": f"Urgency or phishing pattern detected: {pattern}"
                    })
                    break

        except Exception as e:
            extracted.extraction_warnings.append(f"Email parsing error: {str(e)}")

        extracted.segments = segments
        return extracted
