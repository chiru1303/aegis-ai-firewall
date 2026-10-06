"""
Universal Image Parser integrating OCR Pipeline and EXIF metadata into typed Segments.
Treats OCR text and image EXIF metadata as UNTRUSTED content with provenance tracking.
"""
import hashlib
import uuid
from typing import List
from .base import BaseParser, ExtractedContent
from app.models.schemas import Segment
from app.ocr.pipeline import OCRPipeline

class ImageParser(BaseParser):
    supported_types = ['image/png', 'image/jpeg', 'image/jpg', 'image/webp', 'image/tiff', 'image/bmp', 'image/gif']

    def __init__(self):
        self.ocr_pipeline = OCRPipeline()

    def can_parse(self, mime_type: str, filename: str) -> bool:
        fn_lower = filename.lower()
        return mime_type in self.supported_types or any(fn_lower.endswith(ext) for ext in ['.png', '.jpg', '.jpeg', '.webp', '.tiff', '.bmp', '.gif'])

    async def parse(self, content: bytes, filename: str = '', mime_type: str = '') -> ExtractedContent:
        extracted = ExtractedContent(
            text='',
            source_type='image'
        )
        extracted.content_hash = hashlib.sha256(content).hexdigest()
        segments: List[Segment] = []

        ocr_res = await self.ocr_pipeline.process_image(content)
        if not ocr_res.text.strip():
            extracted.extraction_warnings.append("Image yielded no inspectable OCR text")
        elif ocr_res.confidence < 0.4:
            extracted.extraction_warnings.append("OCR confidence is too low for automatic approval")

        # 1. EXIF Metadata Segments
        if ocr_res.exif_data:
            extracted.metadata['exif'] = ocr_res.exif_data
            for tag_name, val in ocr_res.exif_data.items():
                segments.append(Segment(
                    id=f"seg-img-exif-{tag_name}-{uuid.uuid4().hex[:6]}",
                    text=val,
                    source_type="image",
                    location=f"image:exif:{tag_name}",
                    visibility="metadata",
                    trust="UNTRUSTED"
                ))

        # 2. QR Code Segments
        for i, qr in enumerate(ocr_res.qr_codes):
            extracted.hidden_content.append(qr)
            segments.append(Segment(
                id=f"seg-img-qr-{i}-{uuid.uuid4().hex[:6]}",
                text=qr,
                source_type="image",
                location=f"image:qr_code:{i+1}",
                visibility="hidden",
                trust="UNTRUSTED"
            ))

        # 3. OCR Text Body
        if ocr_res.text:
            extracted.text = ocr_res.text
            segments.append(Segment(
                id=f"seg-img-ocr-{uuid.uuid4().hex[:6]}",
                text=ocr_res.text,
                source_type="ocr",
                location="image:ocr:body",
                visibility="visible",
                trust="UNTRUSTED",
                metadata={"ocr_confidence": ocr_res.confidence}
            ))

        extracted.extraction_warnings.extend(ocr_res.warnings)
        extracted.segments = segments
        return extracted
