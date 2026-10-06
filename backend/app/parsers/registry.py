"""
Parser Registry for Aegis AI Firewall
Manages content analyzers for multiple file formats with graceful import error handling.
"""
from typing import List, Optional
import mimetypes
from .base import BaseParser

class ParserRegistry:
    def __init__(self):
        self._parsers: List[BaseParser] = []

    def register(self, parser_instance: BaseParser):
        self._parsers.append(parser_instance)

    def get_parser(self, mime_type: str, filename: str) -> Optional[BaseParser]:
        if not mime_type and filename:
            guessed_mime, _ = mimetypes.guess_type(filename)
            if guessed_mime:
                mime_type = guessed_mime

        for parser in self._parsers:
            try:
                if parser.can_parse(mime_type, filename):
                    return parser
            except Exception:
                continue
        return None

# Singleton instance
registry = ParserRegistry()

def register_default_parsers():
    parsers_to_load = [
        ("pdf_parser", "PDFParser"),
        ("docx_parser", "DOCXParser"),
        ("html_parser", "HTMLParser"),
        ("markdown_parser", "MarkdownParser"),
        ("json_parser", "JSONParser"),
        ("xml_parser", "XMLParser"),
        ("email_parser", "EmailParser"),
        ("code_parser", "CodeParser"),
        ("image_parser", "ImageParser"),
        ("text_parser", "TextParser"),
    ]

    import importlib
    for module_name, class_name in parsers_to_load:
        try:
            mod = importlib.import_module(f".{module_name}", package="app.parsers")
            cls = getattr(mod, class_name)
            registry.register(cls())
        except Exception:
            # Dependency not present in current environment (e.g. fitz or docx)
            pass

register_default_parsers()
