"""
Universal PDF Document Parser using PyMuPDF (fitz) with OCR fallback.
Extracts page body text, annotations/comments, form fields, document metadata,
embedded file references, and scanned page text into typed Segments with exact locations.
"""
import hashlib
import io
import re
import uuid
from typing import List, Dict, Any
from .base import BaseParser, ExtractedContent
from app.models.schemas import Segment

try:
    import fitz  # PyMuPDF
    _HAS_FITZ = True
except ImportError:
    fitz = None
    _HAS_FITZ = False

try:
    from PIL import Image
    import pytesseract
    _HAS_OCR = True
except ImportError:
    Image = None
    pytesseract = None
    _HAS_OCR = False


class PDFParser(BaseParser):
    supported_types = ['application/pdf']
    MAX_PAGES = 100
    MAX_EMBEDDED_IMAGES = 25

    def can_parse(self, mime_type: str, filename: str) -> bool:
        return mime_type in self.supported_types or filename.lower().endswith('.pdf')

    async def parse(self, content: bytes, filename: str = '', mime_type: str = '') -> ExtractedContent:
        extracted = ExtractedContent(
            text='',
            source_type='pdf'
        )
        extracted.content_hash = hashlib.sha256(content).hexdigest()
        segments: List[Segment] = []
        embedded_image_count = 0
        ocr_by_xref = {}

        # Check basic PDF structure validity
        if not content.startswith(b'%PDF-') or (b'%%EOF' not in content and b'xref' not in content and b'obj' not in content):
            extracted.extraction_warnings.append("Malformed or corrupted PDF: missing valid PDF structure/trailer.")
            return extracted

        if not _HAS_FITZ:
            # Resilient fallback: extract ASCII/UTF-8 text sequences from PDF binary
            matches = re.findall(rb'[\x20-\x7E\t\r\n]{4,}', content)
            raw_text = b' '.join(matches).decode('latin1', errors='replace')
            extracted.text = raw_text[:50000]
            if extracted.text:
                segments.append(Segment(
                    id=f"seg-pdf-stream-{uuid.uuid4().hex[:6]}",
                    text=extracted.text,
                    source_type="pdf",
                    location="page 1 / stream_text",
                    visibility="visible",
                    trust="UNTRUSTED"
                ))
            extracted.extraction_warnings.append("PyMuPDF not installed; extracted readable stream text.")
            extracted.segments = segments
            return extracted

        try:
            doc = fitz.open(stream=content, filetype="pdf")
            extracted.metadata = doc.metadata or {}

            # 1. Document Metadata Segments
            if doc.metadata:
                for k, v in doc.metadata.items():
                    if v and isinstance(v, str) and v.strip():
                        segments.append(Segment(
                            id=f"seg-pdf-meta-{k}-{uuid.uuid4().hex[:6]}",
                            text=v.strip(),
                            source_type="pdf",
                            location=f"pdf:metadata:{k}",
                            visibility="metadata",
                            trust="UNTRUSTED"
                        ))

            # 2. Embedded files
            try:
                emb_names = doc.embfile_names() if hasattr(doc, 'embfile_names') else []
                for name in emb_names:
                    extracted.extraction_warnings.append("Embedded PDF attachment requires separate inspection")
                    extracted.embedded_objects.append(name)
                    segments.append(Segment(
                        id=f"seg-pdf-emb-{uuid.uuid4().hex[:6]}",
                        text=f"Embedded file: {name}",
                        source_type="pdf",
                        location=f"pdf:embedded_file:{name}",
                        visibility="metadata",
                        trust="UNTRUSTED"
                    ))
            except Exception:
                extracted.extraction_warnings.append("PDF attachment extraction failed")

            pages_to_process = min(len(doc), self.MAX_PAGES)
            if len(doc) > self.MAX_PAGES:
                extracted.extraction_warnings.append(f"PDF exceeded max pages ({self.MAX_PAGES}). Truncated.")

            text_blocks = []
            for i in range(pages_to_process):
                page = doc[i]
                page_no = i + 1

                # Page body text
                page_text = page.get_text()
                if page_text and page_text.strip():
                    clean_page_text = page_text.strip()
                    text_blocks.append(clean_page_text)
                    segments.append(Segment(
                        id=f"seg-pdf-page-{page_no}-{uuid.uuid4().hex[:6]}",
                        text=clean_page_text,
                        source_type="pdf",
                        location=f"page {page_no} / text",
                        visibility="visible",
                        trust="UNTRUSTED"
                    ))
                elif _HAS_OCR:
                    # OCR Fallback for scanned pages
                    try:
                        pix = page.get_pixmap(dpi=150)
                        img = Image.open(io.BytesIO(pix.tobytes("png")))
                        ocr_txt = pytesseract.image_to_string(img, timeout=10).strip()
                        if ocr_txt:
                            text_blocks.append(ocr_txt)
                            segments.append(Segment(
                                id=f"seg-pdf-ocr-{page_no}-{uuid.uuid4().hex[:6]}",
                                text=ocr_txt,
                                source_type="pdf",
                                location=f"page {page_no} / ocr",
                                visibility="visible",
                                trust="UNTRUSTED"
                            ))
                        else:
                            extracted.extraction_warnings.append("Scanned page yielded no inspectable OCR text")
                    except Exception as exc:
                        extracted.extraction_warnings.append(f"Scanned page OCR failed: {type(exc).__name__}")
                else:
                    extracted.extraction_warnings.append("Scanned page OCR unavailable")

                # OCR placed images even when a page also contains selectable
                # text. Mixed text/image pages are common carriers for hidden
                # instructions, so text-layer presence is not a safe shortcut.
                try:
                    page_images = page.get_images(full=True)
                    for image_no, image_info in enumerate(page_images, start=1):
                        xref = image_info[0]
                        if not xref:
                            continue
                        embedded_image_count += 1
                        if embedded_image_count > self.MAX_EMBEDDED_IMAGES:
                            extracted.extraction_warnings.append(
                                f"PDF embedded-image budget exceeded ({self.MAX_EMBEDDED_IMAGES})"
                            )
                            break
                        if xref not in ocr_by_xref:
                            try:
                                image_data = doc.extract_image(xref)
                                image_bytes = image_data.get("image", b"")
                                image_ext = image_data.get("ext", "bin")
                                from .image_parser import ImageParser
                                image_parser = ImageParser()
                                ocr_by_xref[xref] = await image_parser.parse(
                                    image_bytes,
                                    f"pdf-image-{xref}.{image_ext}",
                                    f"image/{image_ext}",
                                )
                            except Exception as exc:
                                extracted.extraction_warnings.append(
                                    f"PDF embedded image OCR failed: {type(exc).__name__}"
                                )
                                continue
                        image_result = ocr_by_xref[xref]
                        extracted.extraction_warnings.extend(image_result.extraction_warnings)
                        for image_segment in image_result.segments:
                            image_segment.source_type = "pdf"
                            image_segment.location = (
                                f"page {page_no} / image {image_no} / {image_segment.location}"
                            )
                            segments.append(image_segment)
                        if image_result.text.strip():
                            text_blocks.append(
                                f"[page {page_no} image {image_no} OCR]\n{image_result.text}"
                            )
                except Exception as exc:
                    extracted.extraction_warnings.append(
                        f"PDF embedded image enumeration failed: {type(exc).__name__}"
                    )

                # Page Annotations / Comments
                try:
                    for annot in page.annots():
                        info = annot.info or {}
                        annot_content = info.get("content", "") or annot.get_text() or ""
                        if annot_content and annot_content.strip():
                            clean_annot = annot_content.strip()
                            extracted.comments.append(clean_annot)
                            segments.append(Segment(
                                id=f"seg-pdf-annot-{page_no}-{uuid.uuid4().hex[:6]}",
                                text=clean_annot,
                                source_type="pdf",
                                location=f"page {page_no} / annotation",
                                visibility="hidden",
                                trust="UNTRUSTED"
                            ))
                except Exception:
                    extracted.extraction_warnings.append("PDF annotation extraction failed")

                # Interactive Form Fields (Widgets)
                try:
                    for widget in page.widgets():
                        val = widget.field_value
                        if val and isinstance(val, str) and val.strip():
                            clean_val = val.strip()
                            segments.append(Segment(
                                id=f"seg-pdf-widget-{page_no}-{uuid.uuid4().hex[:6]}",
                                text=clean_val,
                                source_type="pdf",
                                location=f"page {page_no} / form_field:{widget.field_name or 'unnamed'}",
                                visibility="visible",
                                trust="UNTRUSTED"
                            ))
                except Exception:
                    extracted.extraction_warnings.append("PDF form-field extraction failed")

                # Hyperlinks
                for link in page.get_links():
                    uri = link.get("uri")
                    if uri:
                        extracted.links.append(uri)

                # Script / launch action security check
                raw_text_lower = page.get_text("text").lower()
                if "/javascript" in raw_text_lower or "/launch" in raw_text_lower:
                    extracted.suspicious_elements.append({
                        "page": page_no,
                        "type": "executable_script_reference",
                        "severity": "HIGH"
                    })

            extracted.text = "\n\n".join(text_blocks)

        except Exception as e:
            extracted.extraction_warnings.append(f"PDF extraction error: {str(e)}")

        extracted.segments = segments
        return extracted
