"""
Aegis AI Firewall - Hardened Web Content Fetcher with Bulletproof SSRF Defense
Protects against:
- IPv4/IPv6 private, loopback, link-local, carrier-grade NAT, multicast
- Cloud metadata IP (AWS/GCP/Azure 169.254.169.254, AWS IPv6 fd00:ec2::254)
- IPv4-mapped IPv6 addresses (::ffff:127.0.0.1, ::ffff:7f00:1)
- DNS rebinding TOCTOU attacks (resolves all IPs via getaddrinfo)
- Open Redirect SSRF bypass (manual validation of redirect targets up to max 3 hops)
- Localhost, internal names, and mDNS (.local, .internal, .lan, etc.)
- Resource exhaustion (streaming with strict byte size limit)
"""
import httpx
import ipaddress
import socket
from urllib.parse import urlparse, urljoin
from typing import Optional, List, Set, Tuple
from .base import ExtractedContent
from .html_parser import HTMLParser

BLOCKED_HOST_SUFFIXES = (
    ".local",
    ".internal",
    ".lan",
    ".home.arpa",
    ".localhost",
    ".corp",
    ".intra",
)

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
}

BLOCKED_IP_STRINGS = {
    "169.254.169.254",   # AWS/GCP/Azure IMDSv4
    "fd00:ec2::254",       # AWS IMDSv6
    "100.100.100.200",     # Alibaba Cloud IMDS
}


class WebFetcher:
    def __init__(self, timeout: int = 10, max_size: int = 5 * 1024 * 1024, max_redirects: int = 3):
        self.timeout = timeout
        self.max_size = max_size
        self.max_redirects = max_redirects
        self.html_parser = HTMLParser()

    @staticmethod
    def is_safe_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """
        Comprehensive check against all non-public/dangerous IP address spaces.
        Handles IPv4, IPv6, and IPv4-mapped IPv6 addresses.
        """
        # Unwrap IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped:
            ip_obj = ip_obj.ipv4_mapped

        # Check standard properties
        if (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        ):
            return False

        # Additional specific checks
        ip_str = str(ip_obj).lower()
        if ip_str in BLOCKED_IP_STRINGS:
            return False

        # Check IPv4 carrier-grade NAT (100.64.0.0/10)
        if isinstance(ip_obj, ipaddress.IPv4Address):
            cgnat = ipaddress.IPv4Network("100.64.0.0/10")
            if ip_obj in cgnat:
                return False
            # Check 0.0.0.0/8
            if ip_obj in ipaddress.IPv4Network("0.0.0.0/8"):
                return False

        # Check IPv6 unique local (fc00::/7)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            if ip_obj in ipaddress.IPv6Network("fc00::/7"):
                return False

        return True

    def validate_url_and_resolve(self, url: str) -> Tuple[bool, str, List[str]]:
        """
        Validates URL scheme, hostname, and resolves all DNS records.
        Returns (is_safe, error_message, list_of_resolved_ips).
        """
        try:
            parsed = urlparse(url)
        except Exception as e:
            return False, f"Malformed URL: {e}", []

        if parsed.scheme not in ("http", "https"):
            return False, f"Unsupported scheme '{parsed.scheme}'. Only http and https allowed.", []

        hostname = parsed.hostname
        if not hostname:
            return False, "URL contains no valid hostname.", []

        norm_host = hostname.strip().lower().rstrip(".")

        # Block direct localhost and dangerous hostnames
        if norm_host in BLOCKED_HOSTNAMES:
            return False, f"Access to '{norm_host}' is blocked for security.", []

        for suffix in BLOCKED_HOST_SUFFIXES:
            if norm_host.endswith(suffix):
                return False, f"Access to internal domain suffix '{suffix}' is blocked.", []

        # Check if hostname is an IP literal
        try:
            ip_obj = ipaddress.ip_address(norm_host)
            if not self.is_safe_ip(ip_obj):
                return False, f"Direct access to internal IP '{norm_host}' blocked.", []
            return True, "", [str(ip_obj)]
        except ValueError:
            pass  # Not an IP literal; proceed to DNS resolution

        # Resolve all IPs for hostname (both IPv4 and IPv6)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        resolved_ips: List[str] = []
        try:
            addr_info = socket.getaddrinfo(norm_host, port, type=socket.SOCK_STREAM)
            for family, socktype, proto, canonname, sockaddr in addr_info:
                ip_str = sockaddr[0]
                resolved_ips.append(ip_str)
        except socket.gaierror as e:
            return False, f"DNS resolution failed for '{norm_host}': {e}", []

        if not resolved_ips:
            return False, f"Could not resolve any IP address for '{norm_host}'.", []

        # Verify that EVERY resolved IP address is safe
        for ip_str in resolved_ips:
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if not self.is_safe_ip(ip_obj):
                    return False, f"Hostname '{norm_host}' resolved to restricted IP '{ip_str}' (SSRF prevented).", []
            except ValueError:
                return False, f"Invalid resolved IP '{ip_str}'.", []

        return True, "", resolved_ips

    async def _fetch_public_resource(self, url: str, accept: str, max_size: int):
        """Fetch one public resource, revalidating every redirect and pinning DNS."""
        current_url = url
        headers = {"User-Agent": "Aegis-AI-Firewall/1.0 (Security Scanner)", "Accept": accept}
        async with httpx.AsyncClient(follow_redirects=False, timeout=self.timeout, trust_env=False) as client:
            for redirect_count in range(self.max_redirects + 1):
                safe, reason, addresses = self.validate_url_and_resolve(current_url)
                if not safe:
                    raise ValueError(f"SSRF check failed: {reason}")
                parsed = urlparse(current_url)
                if parsed.username or parsed.password:
                    raise ValueError("URL credentials are forbidden")
                pinned_url = httpx.URL(current_url).copy_with(host=addresses[0])
                pinned_headers = {**headers, "Host": parsed.netloc}
                async with client.stream(
                    "GET", pinned_url, headers=pinned_headers,
                    extensions={"sni_hostname": parsed.hostname},
                ) as response:
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location")
                        if not location or redirect_count >= self.max_redirects:
                            raise ValueError("Invalid or excessive redirects")
                        current_url = urljoin(current_url, location)
                        continue
                    response.raise_for_status()
                    content = bytearray()
                    async for chunk in response.aiter_bytes():
                        content.extend(chunk)
                        if len(content) > max_size:
                            raise ValueError("Remote resource exceeds its byte budget")
                    return bytes(content), current_url, response.headers.get("content-type", "").split(";", 1)[0].lower()
        raise ValueError("Resource could not be fetched")

    async def fetch_and_parse(self, url: str) -> ExtractedContent:
        try:
            page_bytes, current_url, response_type = await self._fetch_public_resource(
                url, "text/html,application/xhtml+xml", self.max_size
            )
            if response_type not in ("text/html", "application/xhtml+xml"):
                raise ValueError(f"Unsupported web response type: {response_type or 'unknown'}")
            from .budget import parse_with_budget
            result = await parse_with_budget(self.html_parser, page_bytes, "web-page.html", response_type)
            result.source_type = "web"
            result.metadata["source_url"] = current_url
            result.metadata["trust"] = "UNTRUSTED"
            image_sources = result.metadata.pop("image_sources", [])
            if image_sources:
                from .image_parser import ImageParser
                from .sniff import sniff_mime_type
                image_parser = ImageParser()
                image_text = []
                for image_no, source in enumerate(image_sources[:5], start=1):
                    try:
                        image_bytes, image_url, _declared = await self._fetch_public_resource(
                            urljoin(current_url, source), "image/*", 2 * 1024 * 1024
                        )
                        mime = sniff_mime_type(image_bytes, image_url.rsplit("/", 1)[-1])
                        if not mime.startswith("image/"):
                            raise ValueError("Remote resource is not a supported raster image")
                        image_result = await parse_with_budget(
                            image_parser, image_bytes,
                            image_url.rsplit("/", 1)[-1] or f"image-{image_no}", mime
                        )
                        result.extraction_warnings.extend(image_result.extraction_warnings)
                        for segment in image_result.segments:
                            segment.source_type = "web"
                            segment.location = f"web:image:{image_no}:{segment.location}"
                            result.segments.append(segment)
                        if image_result.text.strip():
                            image_text.append(f"[image {image_no} OCR]\n{image_result.text}")
                    except Exception as exc:
                        result.extraction_warnings.append(
                            f"Web image {image_no} could not be securely inspected: {type(exc).__name__}"
                        )
                if image_text:
                    result.text = "\n".join(filter(None, [result.text, *image_text]))
            return result
        except Exception as e:
            extracted = ExtractedContent(text="", source_type="web")
            extracted.extraction_warnings.append(f"Web fetch error: {str(e)}")
            return extracted
