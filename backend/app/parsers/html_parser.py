"""
Universal HTML Document Parser with deep segment extraction.
Extracts visible text, hidden CSS elements (display:none, zero font, off-screen, white-on-white),
HTML comments, metadata, script/style blocks, form inputs, and attribute text into typed Segments.
"""
import hashlib
import re
import uuid
import base64
import binascii
from typing import List, Dict, Any
from .base import BaseParser, ExtractedContent
from app.models.schemas import Segment

try:
    from bs4 import BeautifulSoup, Comment
    _HAS_BS4 = True
except ImportError:
    BeautifulSoup = None
    Comment = None
    _HAS_BS4 = False

HIDDEN_STYLE_REGEX = re.compile(
    r'(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0(?:px)?|'
    r'position\s*:\s*absolute\s*;\s*left\s*:\s*-\d+px|left\s*:\s*-\d{3,}px|top\s*:\s*-\d{3,}px|'
    r'color\s*:\s*(?:#fff(?:fff)?|white)\s*;\s*background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white))',
    re.IGNORECASE
)

class HTMLParser(BaseParser):
    supported_types = ['text/html', 'application/xhtml+xml']
    MAX_INLINE_IMAGES = 5
    MAX_INLINE_IMAGE_BYTES = 2 * 1024 * 1024

    def can_parse(self, mime_type: str, filename: str) -> bool:
        return mime_type in self.supported_types or filename.lower().endswith(('.html', '.htm', '.xhtml'))

    async def parse(self, content: bytes, filename: str = '', mime_type: str = '') -> ExtractedContent:
        extracted = ExtractedContent(
            text='',
            source_type='web'
        )
        extracted.content_hash = hashlib.sha256(content).hexdigest()
        html_text = content.decode('utf-8', errors='replace')
        segments: List[Segment] = []

        if not _HAS_BS4:
            # Fallback regex extraction
            comments = re.findall(r'<!--(.*?)-->', html_text, flags=re.DOTALL)
            for i, c in enumerate(comments):
                c_clean = c.strip()
                if c_clean:
                    extracted.comments.append(c_clean)
                    segments.append(Segment(
                        id=f"seg-html-comment-{i}-{uuid.uuid4().hex[:6]}",
                        text=c_clean,
                        source_type="web",
                        location=f"html:comment:{i+1}",
                        visibility="hidden",
                        trust="UNTRUSTED"
                    ))

            scripts = re.findall(r'<script[^>]*>(.*?)</script>', html_text, flags=re.DOTALL | re.IGNORECASE)
            for i, s in enumerate(scripts):
                s_clean = s.strip()
                if s_clean:
                    extracted.scripts.append(s_clean)
                    segments.append(Segment(
                        id=f"seg-html-script-{i}-{uuid.uuid4().hex[:6]}",
                        text=s_clean,
                        source_type="web",
                        location=f"html:script:{i+1}",
                        visibility="hidden",
                        trust="UNTRUSTED"
                    ))

            hidden_matches = re.findall(
                r'<[^>]+style=["\'][^"\']*(?:display:\s*none|font-size:\s*0|visibility:\s*hidden)[^"\']*["\'][^>]*>(.*?)</[^>]+>',
                html_text,
                flags=re.DOTALL | re.IGNORECASE,
            )
            for i, h in enumerate(hidden_matches):
                h_clean = re.sub(r'<[^>]+>', ' ', h).strip()
                if h_clean:
                    extracted.hidden_content.append(h_clean)
                    segments.append(Segment(
                        id=f"seg-html-hidden-{i}-{uuid.uuid4().hex[:6]}",
                        text=h_clean,
                        source_type="web",
                        location=f"html:hidden_style:{i+1}",
                        visibility="hidden",
                        trust="UNTRUSTED"
                    ))

            # Title tag
            title_m = re.search(r'<title[^>]*>(.*?)</title>', html_text, flags=re.DOTALL | re.IGNORECASE)
            if title_m and title_m.group(1).strip():
                t_str = title_m.group(1).strip()
                extracted.metadata['title'] = t_str
                segments.append(Segment(
                    id=f"seg-html-title-{uuid.uuid4().hex[:6]}",
                    text=t_str,
                    source_type="web",
                    location="html:title",
                    visibility="metadata",
                    trust="UNTRUSTED"
                ))

            # Meta tags
            meta_matches = re.findall(r'<meta\s+[^>]*content=["\']([^"\']+)["\'][^>]*>', html_text, flags=re.IGNORECASE)
            for i, mc in enumerate(meta_matches):
                if mc.strip():
                    segments.append(Segment(
                        id=f"seg-html-meta-{i}-{uuid.uuid4().hex[:6]}",
                        text=mc.strip(),
                        source_type="web",
                        location=f"html:meta:{i+1}",
                        visibility="metadata",
                        trust="UNTRUSTED"
                    ))

            # Attributes: alt, title, aria-label
            for attr in ['alt', 'title', 'aria-label']:
                for m in re.finditer(rf'{attr}=["\']([^"\']+)["\']', html_text, flags=re.IGNORECASE):
                    val = m.group(1).strip()
                    if val:
                        segments.append(Segment(
                            id=f"seg-html-attr-{uuid.uuid4().hex[:6]}",
                            text=val,
                            source_type="web",
                            location=f"html:tag[{attr}]",
                            visibility="metadata",
                            trust="UNTRUSTED"
                        ))

            # Hidden form inputs
            for m in re.finditer(r'<input\s+[^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']+)["\'][^>]*>', html_text, flags=re.IGNORECASE):
                val = m.group(1).strip()
                if val:
                    segments.append(Segment(
                        id=f"seg-html-inp-hid-{uuid.uuid4().hex[:6]}",
                        text=val,
                        source_type="web",
                        location="html:form:input[hidden]",
                        visibility="hidden",
                        trust="UNTRUSTED"
                    ))

            clean = re.sub(r'<script[^>]*>.*?</script>', '', html_text, flags=re.DOTALL | re.IGNORECASE)
            clean = re.sub(r'<style[^>]*>.*?</style>', '', clean, flags=re.DOTALL | re.IGNORECASE)
            clean = re.sub(r'<!--.*?-->', '', clean, flags=re.DOTALL)
            clean = re.sub(r'<[^>]+>', ' ', clean)
            extracted.text = re.sub(r'\s+', ' ', clean).strip()
            if extracted.text:
                segments.append(Segment(
                    id=f"seg-html-body-{uuid.uuid4().hex[:6]}",
                    text=extracted.text,
                    source_type="web",
                    location="html:body",
                    visibility="visible",
                    trust="UNTRUSTED"
                ))
            extracted.segments = segments
            return extracted

        try:
            soup = BeautifulSoup(html_text, 'html.parser')

            # 1. Metadata (title, meta tags)
            title_tag = soup.find('title')
            if title_tag and title_tag.string:
                title_text = title_tag.string.strip()
                extracted.metadata['title'] = title_text
                segments.append(Segment(
                    id=f"seg-html-title-{uuid.uuid4().hex[:6]}",
                    text=title_text,
                    source_type="web",
                    location="html:title",
                    visibility="metadata",
                    trust="UNTRUSTED"
                ))

            for meta in soup.find_all('meta'):
                content_val = meta.get('content', '').strip()
                name_val = meta.get('name') or meta.get('property') or meta.get('http-equiv') or 'meta'
                if content_val:
                    segments.append(Segment(
                        id=f"seg-html-meta-{uuid.uuid4().hex[:6]}",
                        text=content_val,
                        source_type="web",
                        location=f"html:meta:{name_val}",
                        visibility="metadata",
                        trust="UNTRUSTED"
                    ))

            # OCR inline image payloads too. Alt text alone does not inspect
            # image pixels and can be deliberately misleading.
            image_sources = []
            inline_image_texts = []
            inline_images = 0
            media_refs = []
            for image in soup.find_all(['img', 'source']):
                if image.get('src'):
                    media_refs.append(str(image.get('src')).strip())
                if image.get('srcset'):
                    for candidate in str(image.get('srcset')).split(','):
                        candidate_url = candidate.strip().split(None, 1)[0] if candidate.strip() else ""
                        if candidate_url:
                            media_refs.append(candidate_url)
            for image_no, src in enumerate(dict.fromkeys(media_refs), start=1):
                if src.lower().startswith('data:image/'):
                    inline_images += 1
                    if inline_images > self.MAX_INLINE_IMAGES:
                        extracted.extraction_warnings.append(
                            f"HTML inline image budget exceeded ({self.MAX_INLINE_IMAGES})"
                        )
                        continue
                    try:
                        header, encoded = src.split(',', 1)
                        if ';base64' not in header.lower():
                            raise ValueError("Only base64 inline raster images are supported")
                        if len(encoded) > self.MAX_INLINE_IMAGE_BYTES * 4 // 3 + 8:
                            raise ValueError("Inline image exceeds OCR byte budget")
                        image_bytes = base64.b64decode(encoded, validate=True)
                        if len(image_bytes) > self.MAX_INLINE_IMAGE_BYTES:
                            raise ValueError("Inline image exceeds OCR byte budget")
                        from .sniff import sniff_mime_type
                        mime = sniff_mime_type(image_bytes, "inline-image")
                        if not mime.startswith('image/'):
                            raise ValueError("Inline payload is not a recognized raster image")
                        from .image_parser import ImageParser
                        image_result = await ImageParser().parse(image_bytes, f"html-image-{image_no}", mime)
                        extracted.extraction_warnings.extend(image_result.extraction_warnings)
                        for image_segment in image_result.segments:
                            image_segment.source_type = "web"
                            image_segment.location = f"html:image:{image_no}:{image_segment.location}"
                            segments.append(image_segment)
                        if image_result.text.strip():
                            inline_image_texts.append(f"[inline image {image_no} OCR]\n{image_result.text}")
                    except (ValueError, binascii.Error) as exc:
                        extracted.extraction_warnings.append(f"HTML inline image requires review: {str(exc)[:120]}")
                    except Exception:
                        extracted.extraction_warnings.append("HTML inline image OCR failed")
                elif src and not src.startswith('#'):
                    image_sources.append(src)
            if image_sources:
                extracted.metadata['image_sources'] = image_sources[:self.MAX_INLINE_IMAGES + 1]
                if len(image_sources) > self.MAX_INLINE_IMAGES:
                    extracted.extraction_warnings.append(
                        f"HTML remote image budget exceeded ({self.MAX_INLINE_IMAGES})"
                    )

            # 2. Links
            for link in soup.find_all('a', href=True):
                href = link['href']
                extracted.links.append(href)

            # 3. Scripts and Styles
            for i, script in enumerate(soup.find_all('script')):
                s_text = script.get_text().strip()
                if s_text:
                    extracted.scripts.append(s_text)
                    segments.append(Segment(
                        id=f"seg-html-script-{i}-{uuid.uuid4().hex[:6]}",
                        text=s_text,
                        source_type="web",
                        location=f"html:script:{i+1}",
                        visibility="hidden",
                        trust="UNTRUSTED"
                    ))

            for i, style in enumerate(soup.find_all('style')):
                st_text = style.get_text().strip()
                if st_text:
                    segments.append(Segment(
                        id=f"seg-html-style-{i}-{uuid.uuid4().hex[:6]}",
                        text=st_text,
                        source_type="web",
                        location=f"html:style:{i+1}",
                        visibility="hidden",
                        trust="UNTRUSTED"
                    ))

            # 4. HTML Comments
            for i, comment in enumerate(soup.find_all(string=lambda text: isinstance(text, Comment))):
                c_text = comment.strip()
                if c_text:
                    extracted.comments.append(c_text)
                    segments.append(Segment(
                        id=f"seg-html-comment-{i}-{uuid.uuid4().hex[:6]}",
                        text=c_text,
                        source_type="web",
                        location=f"html:comment:{i+1}",
                        visibility="hidden",
                        trust="UNTRUSTED"
                    ))

            # 5. Attributes: alt, title, aria-label, data-*
            attr_targets = ['alt', 'title', 'aria-label']
            for tag in soup.find_all():
                for attr in attr_targets:
                    val = tag.get(attr)
                    if val and isinstance(val, str) and val.strip():
                        segments.append(Segment(
                            id=f"seg-html-attr-{uuid.uuid4().hex[:6]}",
                            text=val.strip(),
                            source_type="web",
                            location=f"html:{tag.name}[{attr}]",
                            visibility="metadata",
                            trust="UNTRUSTED"
                        ))
                for attr_name, attr_val in list(tag.attrs.items()):
                    if attr_name.startswith('data-') and isinstance(attr_val, str) and attr_val.strip():
                        segments.append(Segment(
                            id=f"seg-html-data-{uuid.uuid4().hex[:6]}",
                            text=attr_val.strip(),
                            source_type="web",
                            location=f"html:{tag.name}[{attr_name}]",
                            visibility="metadata",
                            trust="UNTRUSTED"
                        ))

            # 6. Hidden form inputs
            for inp in soup.find_all('input', type='hidden'):
                val = inp.get('value', '').strip()
                name = inp.get('name') or inp.get('id') or 'hidden_input'
                if val:
                    segments.append(Segment(
                        id=f"seg-html-hidden-inp-{uuid.uuid4().hex[:6]}",
                        text=val,
                        source_type="web",
                        location=f"html:form:input[hidden]:{name}",
                        visibility="hidden",
                        trust="UNTRUSTED"
                    ))

            # 7. CSS Hidden Containers (display:none, visibility:hidden, font-size:0, offscreen, white-on-white, hidden attr)
            for i, elem in enumerate(soup.find_all(True)):
                style_attr = elem.get('style', '')
                is_css_hidden = bool(style_attr and HIDDEN_STYLE_REGEX.search(style_attr))
                is_attr_hidden = elem.has_attr('hidden') or elem.get('aria-hidden') == 'true'
                if is_css_hidden or is_attr_hidden:
                    hidden_txt = elem.get_text().strip()
                    if hidden_txt:
                        extracted.hidden_content.append(hidden_txt)
                        reason = "style" if is_css_hidden else "hidden_attribute"
                        segments.append(Segment(
                            id=f"seg-html-hidden-{i}-{uuid.uuid4().hex[:6]}",
                            text=hidden_txt,
                            source_type="web",
                            location=f"html:{elem.name}[{reason}]",
                            visibility="hidden",
                            trust="UNTRUSTED"
                        ))

            # 8. Clean visible text (remove script, style, noscript, hidden elements before extracting visible text)
            for elem in soup(["script", "style", "noscript"]):
                elem.extract()

            # Extract paragraphs / body blocks as visible segments
            visible_blocks = []
            for block in soup.find_all(['p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'li', 'td', 'th', 'div']):
                # Only take leaf-ish containers or direct text to avoid massive duplicate nesting
                txt = block.get_text().strip()
                if txt and len(txt) > 3:
                    visible_blocks.append(txt)

            if visible_blocks:
                extracted.text = "\n".join(visible_blocks)
            else:
                extracted.text = re.sub(r'\s+', ' ', soup.get_text()).strip()
            if inline_image_texts:
                extracted.text = "\n".join(filter(None, [extracted.text, *inline_image_texts]))

            if extracted.text:
                segments.append(Segment(
                    id=f"seg-html-body-{uuid.uuid4().hex[:6]}",
                    text=extracted.text,
                    source_type="web",
                    location="html:body",
                    visibility="visible",
                    trust="UNTRUSTED"
                ))

        except Exception as e:
            extracted.extraction_warnings.append(f"HTML extraction warning: {str(e)}")

        extracted.segments = segments
        return extracted
