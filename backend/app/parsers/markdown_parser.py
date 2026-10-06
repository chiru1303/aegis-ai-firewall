"""
Universal Markdown Document Parser with segment extraction.
Extracts body content, front matter, HTML/markdown comments, link titles,
reference links, image alt text, and code fences into typed Segments.
"""
import hashlib
import re
import uuid
import base64
import binascii
from typing import List, Dict, Any
from .base import BaseParser, ExtractedContent
from app.models.schemas import Segment

class MarkdownParser(BaseParser):
    supported_types = ['text/markdown', 'text/x-markdown']
    MAX_INLINE_IMAGES = 5
    MAX_INLINE_IMAGE_BYTES = 2 * 1024 * 1024

    def can_parse(self, mime_type: str, filename: str) -> bool:
        return mime_type in self.supported_types or filename.lower().endswith(('.md', '.markdown'))

    async def parse(self, content: bytes, filename: str = '', mime_type: str = '') -> ExtractedContent:
        extracted = ExtractedContent(
            text='',
            source_type='markdown'
        )
        extracted.content_hash = hashlib.sha256(content).hexdigest()
        segments: List[Segment] = []

        try:
            md_text = content.decode('utf-8', errors='replace')
            extracted.text = md_text
            working_text = md_text

            # 1. YAML / Front Matter at beginning of markdown
            fm_match = re.match(r'^---\s*\n(.*?)\n---\s*\n', working_text, flags=re.DOTALL)
            if fm_match:
                fm_content = fm_match.group(1).strip()
                extracted.metadata['frontmatter'] = fm_content
                segments.append(Segment(
                    id=f"seg-md-fm-{uuid.uuid4().hex[:6]}",
                    text=fm_content,
                    source_type="markdown",
                    location="markdown:frontmatter",
                    visibility="metadata",
                    trust="UNTRUSTED"
                ))
                working_text = working_text[fm_match.end():]

            # 2. HTML comments (<!-- ... -->)
            html_comments = re.findall(r'<!--(.*?)-->', working_text, flags=re.DOTALL)
            for i, hc in enumerate(html_comments):
                hc_clean = hc.strip()
                if hc_clean:
                    extracted.comments.append(hc_clean)
                    segments.append(Segment(
                        id=f"seg-md-comment-{i}-{uuid.uuid4().hex[:6]}",
                        text=hc_clean,
                        source_type="markdown",
                        location=f"markdown:comment:{i+1}",
                        visibility="hidden",
                        trust="UNTRUSTED"
                    ))

            # 3. Markdown comment references [//]: # (comment text)
            md_comments = re.findall(r'\[//\]:\s*#\s*\((.*?)\)', working_text, flags=re.DOTALL)
            for i, mc in enumerate(md_comments):
                mc_clean = mc.strip()
                if mc_clean:
                    extracted.comments.append(mc_clean)
                    segments.append(Segment(
                        id=f"seg-md-ref-comment-{i}-{uuid.uuid4().hex[:6]}",
                        text=mc_clean,
                        source_type="markdown",
                        location=f"markdown:ref_comment:{i+1}",
                        visibility="hidden",
                        trust="UNTRUSTED"
                    ))

            # 4. Code fences (```lang ... ```)
            code_fence_pattern = re.compile(r'```([a-zA-Z0-9_-]*)\n(.*?)```', re.DOTALL)
            for i, match in enumerate(code_fence_pattern.finditer(working_text)):
                lang = match.group(1).strip() or "code"
                code_content = match.group(2).strip()
                if code_content:
                    extracted.scripts.append(code_content)
                    segments.append(Segment(
                        id=f"seg-md-fence-{i}-{uuid.uuid4().hex[:6]}",
                        text=code_content,
                        source_type="markdown",
                        location=f"markdown:code_fence:{lang}:{i+1}",
                        visibility="visible",
                        trust="UNTRUSTED"
                    ))

            # 5. Link titles and image alt text
            # Images: ![alt text](url "optional title")
            img_pattern = re.compile(r'!\[([^\]]*)\]\(([^)\s]+)(?:\s+"([^"]+)")?\)')
            image_sources = []
            inline_image_texts = []
            inline_image_no = 0
            for i, match in enumerate(img_pattern.finditer(working_text)):
                alt_txt = match.group(1).strip()
                img_url = match.group(2).strip()
                img_title = (match.group(3) or '').strip()

                extracted.embedded_objects.append(f"image:{img_url}")
                if img_url.lower().startswith('data:image/'):
                    inline_image_no += 1
                    try:
                        header, encoded = img_url.split(',', 1)
                        if ';base64' not in header.lower() or inline_image_no > self.MAX_INLINE_IMAGES:
                            raise ValueError("Unsupported or excessive inline image")
                        if len(encoded) > self.MAX_INLINE_IMAGE_BYTES * 4 // 3 + 8:
                            raise ValueError("Inline image exceeds OCR byte budget")
                        image_bytes = base64.b64decode(encoded, validate=True)
                        if len(image_bytes) > self.MAX_INLINE_IMAGE_BYTES:
                            raise ValueError("Inline image exceeds OCR byte budget")
                        from .sniff import sniff_mime_type
                        mime = sniff_mime_type(image_bytes, "markdown-image")
                        if not mime.startswith('image/'):
                            raise ValueError("Inline payload is not a supported raster image")
                        from .image_parser import ImageParser
                        image_result = await ImageParser().parse(image_bytes, f"markdown-image-{i}", mime)
                        extracted.extraction_warnings.extend(image_result.extraction_warnings)
                        for image_segment in image_result.segments:
                            image_segment.source_type = "markdown"
                            image_segment.location = f"markdown:image:{i+1}:{image_segment.location}"
                            segments.append(image_segment)
                        if image_result.text.strip():
                            inline_image_texts.append(f"[inline image {i+1} OCR]\n{image_result.text}")
                    except (ValueError, binascii.Error) as exc:
                        extracted.extraction_warnings.append(f"Markdown inline image requires review: {str(exc)[:120]}")
                    except Exception:
                        extracted.extraction_warnings.append("Markdown inline image OCR failed")
                elif img_url and not img_url.startswith('#'):
                    image_sources.append(img_url)
                if alt_txt:
                    segments.append(Segment(
                        id=f"seg-md-img-alt-{i}-{uuid.uuid4().hex[:6]}",
                        text=alt_txt,
                        source_type="markdown",
                        location=f"markdown:image_alt:{i+1}",
                        visibility="metadata",
                        trust="UNTRUSTED"
                    ))
                if img_title:
                    segments.append(Segment(
                        id=f"seg-md-img-title-{i}-{uuid.uuid4().hex[:6]}",
                        text=img_title,
                        source_type="markdown",
                        location=f"markdown:image_title:{i+1}",
                        visibility="metadata",
                        trust="UNTRUSTED"
                    ))

            # Links: [anchor text](url "optional title")
            link_pattern = re.compile(r'\[([^\]]+)\]\(([^)\s]+)(?:\s+"([^"]+)")?\)')
            for i, match in enumerate(link_pattern.finditer(working_text)):
                url = match.group(2).strip()
                link_title = (match.group(3) or '').strip()
                extracted.links.append(url)
                if link_title:
                    segments.append(Segment(
                        id=f"seg-md-link-title-{i}-{uuid.uuid4().hex[:6]}",
                        text=link_title,
                        source_type="markdown",
                        location=f"markdown:link_title:{i+1}",
                        visibility="metadata",
                        trust="UNTRUSTED"
                    ))

            # 6. Primary Body Text (strip code fences and comments)
            clean_body = re.sub(r'```.*?```', '', working_text, flags=re.DOTALL)
            clean_body = re.sub(r'<!--.*?-->', '', clean_body, flags=re.DOTALL)
            clean_body = re.sub(r'\[//\]:\s*#\s*\(.*?\)', '', clean_body, flags=re.DOTALL)
            clean_body = clean_body.strip()

            if inline_image_texts:
                clean_body = "\n\n".join(filter(None, [clean_body, *inline_image_texts]))
                extracted.text = "\n".join(filter(None, [extracted.text, *inline_image_texts]))
            if image_sources:
                extracted.metadata['image_sources'] = image_sources[:self.MAX_INLINE_IMAGES + 1]
                if len(image_sources) > self.MAX_INLINE_IMAGES:
                    extracted.extraction_warnings.append(
                        f"Markdown image budget exceeded ({self.MAX_INLINE_IMAGES})"
                    )

            if clean_body:
                segments.append(Segment(
                    id=f"seg-md-body-{uuid.uuid4().hex[:6]}",
                    text=clean_body,
                    source_type="markdown",
                    location="markdown:body",
                    visibility="visible",
                    trust="UNTRUSTED"
                ))

        except Exception as e:
            extracted.extraction_warnings.append(f"Markdown parsing error: {str(e)}")

        extracted.segments = segments
        return extracted
