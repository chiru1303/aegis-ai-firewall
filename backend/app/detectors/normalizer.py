import unicodedata
import re
import base64
import urllib.parse
import binascii
import html
import codecs
from dataclasses import dataclass, field
from typing import List, Dict, Any

@dataclass
class NormalizationResult:
    original: str
    normalized: str
    decoded_variants: List[str]
    unicode_anomalies: List[Dict[str, Any]]
    zero_width_chars_found: int
    homoglyphs_found: int
    invisible_chars_found: int
    bidi_chars_found: int
    encoding_detected: List[str]
    anomaly_score: float

HOMOGLYPH_MAP = {
    # Cyrillic
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'В': 'B', 'М': 'M', 'Н': 'H',
    'і': 'i', 'І': 'I', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w',
    # Greek
    'ο': 'o', 'ν': 'v', 'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M',
    'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
    # Mathematical & Fullwidth
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4', '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f', 'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i',
    'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r',
    'ｓ': 's', 'ｔ': 't', 'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z',
    'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E', 'Ｆ': 'F', 'Ｇ': 'G', 'Ｈ': 'H', 'Ｉ': 'I',
    'Ｊ': 'J', 'Ｋ': 'K', 'Ｌ': 'L', 'Ｍ': 'M', 'Ｎ': 'N', 'Ｏ': 'O', 'Ｐ': 'P', 'Ｑ': 'Q', 'Ｒ': 'R',
    'Ｓ': 'S', 'Ｔ': 'T', 'Ｕ': 'U', 'Ｖ': 'V', 'Ｗ': 'W', 'Ｘ': 'X', 'Ｙ': 'Y', 'Ｚ': 'Z',
}

ROT13_TARGET_KEYWORDS = {
    'ignore', 'system', 'prompt', 'override', 'developer', 'bypass', 'jailbreak',
    'admin', 'secret', 'reveal', 'disregard', 'unrestricted', 'credentials'
}

MAX_DECODED_LENGTH = 50000
MAX_DECODED_VARIANTS = 30
MAX_EXPANSION_RATIO = 20

class TextNormalizer:
    ZERO_WIDTH = re.compile(r'[\u200B\u200C\u200D\uFEFF\u00AD]')
    BIDI_CTRL = re.compile(r'[\u202A-\u202E\u2066-\u2069]')

    def normalize(self, text: str) -> NormalizationResult:
        anomalies = []
        encodings = set()

        # 1. Count anomalies
        zw_count = len(self.ZERO_WIDTH.findall(text))
        bidi_count = len(self.BIDI_CTRL.findall(text))

        # 2. Base Normalization (NFKC + NFKD to separate accents, combining marks, homoglyphs)
        nfkc = unicodedata.normalize('NFKC', text)
        nfkd = unicodedata.normalize('NFKD', nfkc)
        de_accented = "".join([c for c in nfkd if not unicodedata.combining(c)])
        norm_text = self.ZERO_WIDTH.sub('', de_accented)
        norm_text = self.BIDI_CTRL.sub('', norm_text)

        # 3. Homoglyphs
        homoglyphs_found = 0
        final_chars = []
        for char in norm_text:
            if char in HOMOGLYPH_MAP:
                final_chars.append(HOMOGLYPH_MAP[char])
                homoglyphs_found += 1
            else:
                final_chars.append(char)

        normalized = "".join(final_chars)

        if zw_count > 0: anomalies.append({"type": "zero_width", "count": zw_count})
        if bidi_count > 0: anomalies.append({"type": "bidi_control", "count": bidi_count})
        if homoglyphs_found > 0: anomalies.append({"type": "homoglyph", "count": homoglyphs_found})

        # 4. Decoding (up to 3 levels handled safely with decode-bomb protection)
        decoded_variants = set()

        def safe_decode(t: str, depth: int = 0):
            if depth >= 3 or not t or len(decoded_variants) >= MAX_DECODED_VARIANTS:
                return
            new_variants = []

            # Decode bomb guard: check text length explosion
            if len(t) > MAX_DECODED_LENGTH or (len(text) > 0 and len(t) > len(text) * MAX_EXPANSION_RATIO and len(t) > 10000):
                anomalies.append({"type": "decode_bomb", "description": "Decoded content expansion exceeded safety threshold"})
                return

            # Unicode Escape sequences (\uXXXX and \UXXXXXXXX)
            if r'\u' in t or r'\U' in t:
                try:
                    def _rep_u(m):
                        try:
                            return chr(int(m.group(1), 16))
                        except Exception:
                            return m.group(0)
                    u_dec = re.sub(r'\\u([0-9a-fA-F]{4})', _rep_u, t)
                    u_dec = re.sub(r'\\U([0-9a-fA-F]{8})', _rep_u, u_dec)
                    if u_dec != t and len(u_dec) <= MAX_DECODED_LENGTH:
                        new_variants.append(u_dec)
                        encodings.add("unicode_escape")
                except Exception:
                    pass

            # Embedded or full Base64
            b64_candidates = re.findall(r'[A-Za-z0-9+/]{8,}={0,2}', t)
            for cand in b64_candidates:
                try:
                    dec = base64.b64decode(cand).decode('utf-8', errors='ignore')
                    if dec and 3 <= len(dec) <= MAX_DECODED_LENGTH and any(c.isalnum() for c in dec):
                        new_variants.append(dec)
                        encodings.add("base64")
                except Exception:
                    pass

            # URL Encoded
            if '%' in t:
                try:
                    dec = urllib.parse.unquote(t)
                    if dec != t and len(dec) <= MAX_DECODED_LENGTH:
                        new_variants.append(dec)
                        encodings.add("url")
                except Exception:
                    pass

            # Space-separated or contiguous Hex
            hex_cleaned = re.sub(r'\s+', '', t)
            hex_candidates = re.findall(r'(?:[0-9a-fA-F]{2}){4,}', hex_cleaned)
            for h in hex_candidates:
                try:
                    dec = binascii.unhexlify(h).decode('utf-8', errors='ignore')
                    if dec and 3 <= len(dec) <= MAX_DECODED_LENGTH and any(c.isalnum() for c in dec):
                        new_variants.append(dec)
                        encodings.add("hex")
                except Exception:
                    pass

            # Binary byte sequences
            bin_matches = re.findall(r'\b(?:[01]{8}\s*){3,}\b', t)
            for b in bin_matches:
                try:
                    bytes_list = [int(x, 2) for x in b.split()]
                    dec = bytes(bytes_list).decode('utf-8', errors='ignore')
                    if dec and len(dec) <= MAX_DECODED_LENGTH:
                        new_variants.append(dec)
                        encodings.add("binary")
                except Exception:
                    pass

            # Explicit ROT13 wrapper: rot13('...') or rot13("...")
            if 'rot13' in t.lower():
                rot13_cand = re.findall(r"rot13\(['\"]([^'\"]+)['\"]\)", t, flags=re.IGNORECASE)
                for rc in rot13_cand:
                    try:
                        dec = codecs.decode(rc, 'rot_13')
                        if len(dec) <= MAX_DECODED_LENGTH:
                            new_variants.append(dec)
                            encodings.add("rot13")
                    except Exception:
                        pass

            # Implicit ROT13: check if ROT13 decoding reveals known attack keywords
            try:
                rot13_full = codecs.decode(t, 'rot_13')
                rot13_words = set(re.findall(r'\b[a-zA-Z]{4,}\b', rot13_full.lower()))
                if rot13_words & ROT13_TARGET_KEYWORDS:
                    if len(rot13_full) <= MAX_DECODED_LENGTH:
                        new_variants.append(rot13_full)
                        encodings.add("rot13")
            except Exception:
                pass

            # String.fromCharCode
            if 'fromcharcode' in t.lower():
                code_matches = re.findall(r'fromCharCode\(([\d\s,]+)\)', t, flags=re.IGNORECASE)
                for cm in code_matches:
                    try:
                        chars = [chr(int(c.strip())) for c in cm.split(',') if c.strip().isdigit()]
                        dec = "".join(chars)
                        if len(dec) <= MAX_DECODED_LENGTH:
                            new_variants.append(dec)
                            encodings.add("charcode")
                    except Exception:
                        pass

            # HTML Entities
            if '&' in t and ';' in t:
                try:
                    dec = html.unescape(t)
                    if dec != t and len(dec) <= MAX_DECODED_LENGTH:
                        new_variants.append(dec)
                        encodings.add("html")
                except Exception:
                    pass

            for v in new_variants:
                if v not in decoded_variants and len(decoded_variants) < MAX_DECODED_VARIANTS:
                    decoded_variants.add(v)
                    safe_decode(v, depth + 1)

        safe_decode(normalized)

        # Also add de-spaced variant if inter-letter separators present (I g n o r e, I_g_n_o_r_e, I.g.n.o.r.e)
        if re.search(r'\b[a-zA-Z](?:[\s._][a-zA-Z]){2,}\b', normalized):
            # 1. Squash letters while preserving inter-word spacing
            despaced_words = re.sub(r'[\s._]{2,}', ' <WORD_SEP> ', normalized)
            despaced_clean = re.sub(r'(?<=\b[a-zA-Z])[\s._]+(?=[a-zA-Z]\b)', '', despaced_words).replace('<WORD_SEP>', ' ')
            if despaced_clean != normalized and len(decoded_variants) < MAX_DECODED_VARIANTS:
                decoded_variants.add(despaced_clean)
                encodings.add("spaced_characters")

        # Leet speak translation (4->a, 3->e, 1->i, 0->o, 5->s, 7->t, @->a, $->s)
        leet_chars = set("431057@$")
        if any(c in normalized for c in leet_chars):
            leet_map = str.maketrans("431057@$", "aeiostas")
            leet_decoded = normalized.translate(leet_map)
            if leet_decoded != normalized and len(decoded_variants) < MAX_DECODED_VARIANTS:
                decoded_variants.add(leet_decoded)
                encodings.add("leet_speak")

        # Reversed string variant
        rev_full = normalized[::-1]
        for kw in ["ignore", "system", "prompt", "rule", "bypass", "jailbreak", "dan"]:
            if kw in rev_full.lower():
                if len(decoded_variants) < MAX_DECODED_VARIANTS:
                    decoded_variants.add(rev_full)
                    encodings.add("reversed_text")
                break

        total_anomalies = zw_count + bidi_count + homoglyphs_found + len(encodings) * 2
        score = min(1.0, total_anomalies / 15.0)

        return NormalizationResult(
            original=text,
            normalized=normalized,
            decoded_variants=list(decoded_variants),
            unicode_anomalies=anomalies,
            zero_width_chars_found=zw_count,
            homoglyphs_found=homoglyphs_found,
            invisible_chars_found=zw_count,
            bidi_chars_found=bidi_count,
            encoding_detected=list(encodings),
            anomaly_score=score
        )

normalizer_engine = TextNormalizer()
