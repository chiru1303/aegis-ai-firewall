"""
Universal OCR Pipeline with image preprocessing, EXIF metadata extraction,
contrast enhancement, and injection pattern detection.
"""
from dataclasses import dataclass, field
from typing import List, Tuple, Dict, Any
import io
import time
import re

try:
    from PIL import Image, ImageOps, ImageEnhance
    from PIL.ExifTags import TAGS
    import pytesseract
    _HAS_IMAGING = True
except ImportError:
    Image = None
    ImageOps = None
    ImageEnhance = None
    TAGS = {}
    pytesseract = None
    _HAS_IMAGING = False

try:
    import cv2
    _HAS_CV2 = True
except ImportError:
    cv2 = None
    _HAS_CV2 = False


@dataclass
class OCRResult:
    text: str
    confidence: float
    bounding_boxes: List[dict] = field(default_factory=list)
    image_format: str = ''
    image_size: Tuple[int, int] = (0, 0)
    qr_codes: List[str] = field(default_factory=list)
    exif_data: Dict[str, str] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0


class OCRPipeline:
    def __init__(self, max_size_mb: int = 20):
        self.max_size = max_size_mb * 1024 * 1024
        self.max_frames = 10
        self.max_total_pixels = 40_000_000
        self.supported_formats = {'PNG', 'JPEG', 'JPG', 'WEBP', 'TIFF', 'BMP', 'GIF'}

    def _normalize_text(self, text: str) -> str:
        text = re.sub(r'\s+', ' ', text)
        return text.strip()

    def _detect_injection_patterns(self, text: str, result: OCRResult):
        suspicious = [r'ignore previous', r'system prompt', r'you are now', r'bypass', r'override', r'developer mode']
        lower_text = text.lower()
        for pat in suspicious:
            if re.search(pat, lower_text):
                result.warnings.append(f"Potential injection pattern detected in OCR: {pat}")

    def _preprocess_image(self, img: "Image.Image") -> "Image.Image":
        """
        Enhance image for OCR: upscale if low-res, convert to grayscale, boost contrast.
        """
        try:
            # Upscale if small (< 1000px on smallest side)
            w, h = img.size
            if min(w, h) < 600:
                scale = min(4.0, max(2.0, 1000.0 / min(w, h)), (20_000_000 / (w*h)) ** .5)
                img = img.resize((int(w * scale), int(h * scale)), Image.Resampling.LANCZOS)

            # Convert to grayscale
            gray = img.convert('L')

            # Contrast stretch
            enhancer = ImageEnhance.Contrast(gray)
            enhanced = enhancer.enhance(2.0)
            return enhanced
        except Exception:
            return img

    async def process_image(self, image_bytes: bytes) -> OCRResult:
        start_time = time.perf_counter()
        result = OCRResult(text='', confidence=0.0)

        if not _HAS_IMAGING or pytesseract is None:
            result.warnings.append("Pillow or pytesseract not installed. OCR unavailable.")
            result.processing_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return result

        if len(image_bytes) > self.max_size:
            result.warnings.append(f"Image exceeds max size of {self.max_size} bytes.")
            result.processing_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
            return result

        try:
            image = Image.open(io.BytesIO(image_bytes))

            # Format validation
            fmt = (image.format or '').upper()
            if fmt not in self.supported_formats:
                result.warnings.append(f"Unsupported image format: {fmt}")
                result.processing_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
                return result

            result.image_format = fmt
            result.image_size = image.size

            # 1. Extract EXIF metadata text (Artist, ImageDescription, UserComment, Software)
            try:
                exif = image.getexif()
                if exif:
                    for tag_id, val in exif.items():
                        tag_name = TAGS.get(tag_id, str(tag_id))
                        if isinstance(val, (str, bytes)):
                            val_str = val.decode('utf-8', errors='ignore') if isinstance(val, bytes) else val
                            val_str = val_str.strip()
                            if val_str:
                                result.exif_data[tag_name] = val_str
            except Exception:
                result.warnings.append("Image metadata extraction failed")

            # OCR and decode every frame: animated images and multipage TIFFs can hide
            # instructions in a frame other than the cover image.
            frame_count = getattr(image, "n_frames", 1)
            frames_to_scan = min(frame_count, self.max_frames)
            if frame_count > self.max_frames:
                result.warnings.append(
                    f"Image frame budget exceeded ({frame_count} frames; scanned {self.max_frames})"
                )
            total_pixels = 0
            text_parts = []
            confidences = []
            for frame_index in range(frames_to_scan):
                image.seek(frame_index)
                frame = image.copy()
                frame_pixels = frame.width * frame.height
                total_pixels += frame_pixels
                if frame_pixels > 20_000_000 or total_pixels > self.max_total_pixels:
                    result.warnings.append("Image frame pixel budget exceeded")
                    break

                if _HAS_CV2:
                    try:
                        import numpy as np
                        cv_frame = np.asarray(frame.convert("RGB"))[:, :, ::-1].copy()
                        detector = cv2.QRCodeDetector()
                        decoded = []
                        if hasattr(detector, "detectAndDecodeMulti"):
                            found, values, _, _ = detector.detectAndDecodeMulti(cv_frame)
                            if found:
                                decoded.extend(values)
                        if not decoded:
                            value, _, _ = detector.detectAndDecode(cv_frame)
                            if value:
                                decoded.append(value)
                        result.qr_codes.extend(value for value in decoded if value)
                    except Exception:
                        result.warnings.append("QR extraction failed for an image frame")

                prep_image = self._preprocess_image(frame)
                data = pytesseract.image_to_data(
                    prep_image, output_type=pytesseract.Output.DICT, timeout=10
                )
                for i in range(len(data['text'])):
                    word = data['text'][i].strip()
                    if not word:
                        continue
                    text_parts.append(word)
                    try:
                        conf = float(data['conf'][i])
                        if conf > 0:
                            confidences.append(conf)
                    except (ValueError, TypeError):
                        pass
                    result.bounding_boxes.append({
                        'text': word,
                        'frame': frame_index + 1,
                        'x': data['left'][i],
                        'y': data['top'][i],
                        'w': data['width'][i],
                        'h': data['height'][i],
                        'conf': data['conf'][i]
                    })

            result.text = self._normalize_text(" ".join(text_parts))
            if confidences:
                result.confidence = round(sum(confidences) / len(confidences) / 100.0, 3)

            # Injection detection belongs to the shared content scanner. Warnings
            # describe extraction failures, rather than reclassifying attacks as parse errors.

        except Exception as e:
            result.warnings.append(f"OCR processing error: {str(e)}")

        result.processing_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return result
