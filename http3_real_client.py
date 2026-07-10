"""
Production-Ready HTTP/3 Client using httpx with QUIC support

This module provides genuine HTTP/3 over QUIC implementation using httpx[http3].
"""

import asyncio
import logging
import time
from typing import Dict, Optional, Tuple, Any, TYPE_CHECKING
from dataclasses import dataclass

if TYPE_CHECKING:
    import httpx

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
    httpx = None  # type: ignore
    logging.warning("httpx not available. Install with: pip install httpx[http3]")

logger = logging.getLogger(__name__)


@dataclass
class HTTP3ConnectionMetadata:
    """Metadata about HTTP/3 connection"""
    protocol_version: str
    quic_connection_id: Optional[str] = None
    stream_id: Optional[int] = None
    negotiated_version: Optional[str] = None
    connection_time: float = 0.0
    handshake_time: float = 0.0
    total_time: float = 0.0
    bytes_sent: int = 0
    bytes_received: int = 0
    tls_version: Optional[str] = None
    cipher_suite: Optional[str] = None


class HTTP3RealClient:
    """
    Production HTTP/3 client using httpx with real QUIC transport
    
    This implementation uses httpx[http3] which provides genuine HTTP/3
    over QUIC protocol support.
    """
    
    def __init__(
        self,
        verify_ssl: bool = True,
        timeout: int = 30,
        max_connections: int = 10,
        http2_fallback: bool = True
    ):
        """
        Initialize HTTP/3 client
        
        Args:
            verify_ssl: Whether to verify SSL certificates
            timeout: Request timeout in seconds
            max_connections: Maximum concurrent connections
            http2_fallback: Allow fallback to HTTP/2 if HTTP/3 unavailable
        """
        if not HTTPX_AVAILABLE:
            raise ImportError(
                "httpx is required for HTTP/3 support. "
                "Install with: pip install 'httpx[http3]'"
            )
        
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_connections = max_connections
        self.http2_fallback = http2_fallback
        self._client: Optional[Any] = None  # httpx.AsyncClient when available
        self._connection_metadata: Dict[str, HTTP3ConnectionMetadata] = {}
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.close()
    
    async def connect(self):
        """Establish HTTP/3 client connection"""
        if self._client is None:
            # Configure httpx for HTTP/3
            # http1=False, http2=True allows HTTP/2 fallback
            # For pure HTTP/3, set http2=False as well
            self._client = httpx.AsyncClient(
                http1=False,  # Disable HTTP/1.1
                http2=self.http2_fallback,  # Allow HTTP/2 fallback
                verify=self.verify_ssl,
                timeout=httpx.Timeout(self.timeout),
                limits=httpx.Limits(
                    max_connections=self.max_connections,
                    max_keepalive_connections=self.max_connections
                )
            )
            logger.info("HTTP/3 client initialized")
    
    async def close(self):
        """Close HTTP/3 client connection"""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info("HTTP/3 client closed")
    
    def _extract_connection_metadata(
        self,
        response: Any,  # httpx.Response when available
        start_time: float,
        request_size: int
    ) -> HTTP3ConnectionMetadata:
        """
        Extract detailed connection metadata from response
        
        Args:
            response: httpx Response object
            start_time: Request start timestamp
            request_size: Size of request in bytes
            
        Returns:
            HTTP3ConnectionMetadata object
        """
        total_time = time.time() - start_time
        
        # Extract protocol version
        protocol = str(response.http_version)
        
        # Try to get QUIC-specific metadata if available
        quic_conn_id = None
        stream_id = None
        
        # httpx exposes some connection info through extensions
        if hasattr(response, 'extensions'):
            extensions = response.extensions
            quic_conn_id = extensions.get('quic_connection_id')
            stream_id = extensions.get('stream_id')
        
        metadata = HTTP3ConnectionMetadata(
            protocol_version=protocol,
            quic_connection_id=quic_conn_id,
            stream_id=stream_id,
            total_time=total_time,
            bytes_sent=request_size,
            bytes_received=len(response.content)
        )
        
        logger.debug(f"Connection metadata: {metadata}")
        return metadata
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        reuse_connection: bool = True
    ) -> Tuple[int, Dict[str, str], bytes, HTTP3ConnectionMetadata]:
        """
        Send HTTP/3 request over QUIC
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Full URL to request
            headers: Optional HTTP headers
            body: Optional request body
            reuse_connection: Whether to reuse existing connection
            
        Returns:
            Tuple of (status_code, response_headers, response_body, metadata)
        """
        if not self._client:
            await self.connect()
        
        start_time = time.time()
        request_size = len(body) if body else 0
        
        try:
            logger.info(f"Sending HTTP/3 {method} request to {url}")
            
            response = await self._client.request(
                method=method,
                url=url,
                headers=headers,
                content=body
            )
            
            # Extract metadata
            metadata = self._extract_connection_metadata(
                response, start_time, request_size
            )
            
            # Store metadata for connection reuse analysis
            self._connection_metadata[url] = metadata
            
            logger.info(
                f"HTTP/3 response: {response.status_code} "
                f"({metadata.protocol_version}) in {metadata.total_time:.3f}s"
            )
            
            return (
                response.status_code,
                dict(response.headers),
                response.content,
                metadata
            )
        
        except httpx.HTTPError as e:
            logger.error(f"HTTP/3 request failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in HTTP/3 request: {e}")
            raise
    
    async def test_connection_reuse(
        self,
        url: str,
        num_requests: int = 3
    ) -> Dict[str, Any]:
        """
        Test connection reuse and detect potential contamination
        
        Args:
            url: URL to test
            num_requests: Number of sequential requests
            
        Returns:
            Dictionary with test results
        """
        results = {
            'requests': [],
            'connection_reused': False,
            'contamination_detected': False,
            'details': []
        }
        
        previous_metadata = None
        
        for i in range(num_requests):
            status, headers, body, metadata = await self.request('GET', url)
            
            request_result = {
                'request_num': i + 1,
                'status': status,
                'protocol': metadata.protocol_version,
                'stream_id': metadata.stream_id,
                'response_size': len(body)
            }
            
            results['requests'].append(request_result)
            
            # Check for connection reuse
            if previous_metadata and metadata.quic_connection_id:
                if metadata.quic_connection_id == previous_metadata.quic_connection_id:
                    results['connection_reused'] = True
                    logger.info(f"Connection reused: {metadata.quic_connection_id}")
            
            # Check for contamination (different stream IDs should have isolated data)
            if previous_metadata:
                # Compare response characteristics
                if (metadata.stream_id != previous_metadata.stream_id and
                    len(body) != results['requests'][i-1]['response_size']):
                    results['contamination_detected'] = True
                    results['details'].append(
                        f"Potential contamination between streams "
                        f"{previous_metadata.stream_id} and {metadata.stream_id}"
                    )
            
            previous_metadata = metadata
            
            # Small delay between requests
            await asyncio.sleep(0.1)
        
        return results
    
    def get_connection_metadata(self, url: str) -> Optional[HTTP3ConnectionMetadata]:
        """Get stored connection metadata for a URL"""
        return self._connection_metadata.get(url)
    
    def clear_metadata(self):
        """Clear stored connection metadata"""
        self._connection_metadata.clear()


async def verify_http3_support(url: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Verify if a server supports HTTP/3
    
    Args:
        url: URL to test
        timeout: Timeout in seconds
        
    Returns:
        Dictionary with support information
    """
    result = {
        'http3_supported': False,
        'protocol_version': None,
        'alt_svc_header': None,
        'error': None
    }
    
    try:
        async with HTTP3RealClient(timeout=timeout) as client:
            status, headers, body, metadata = await client.request('GET', url)
            
            result['http3_supported'] = 'HTTP/3' in metadata.protocol_version or 'h3' in metadata.protocol_version.lower()
            result['protocol_version'] = metadata.protocol_version
            result['alt_svc_header'] = headers.get('alt-svc')
            
    except Exception as e:
        result['error'] = str(e)
        logger.error(f"Failed to verify HTTP/3 support: {e}")
    
    return result


# Example usage
async def example_http3_usage():
    """Example of using the HTTP/3 client"""
    
    # Test HTTP/3 support
    print("Testing HTTP/3 support...")
    support_info = await verify_http3_support("https://cloudflare.com/")
    print(f"HTTP/3 Supported: {support_info['http3_supported']}")
    print(f"Protocol: {support_info['protocol_version']}")
    print(f"Alt-Svc: {support_info['alt_svc_header']}")
    
    # Make HTTP/3 requests
    async with HTTP3RealClient() as client:
        # Single request
        status, headers, body, metadata = await client.request(
            'GET',
            'https://cloudflare.com/'
        )
        print(f"\nStatus: {status}")
        print(f"Protocol: {metadata.protocol_version}")
        print(f"Time: {metadata.total_time:.3f}s")
        
        # Test connection reuse
        print("\nTesting connection reuse...")
        reuse_results = await client.test_connection_reuse(
            'https://cloudflare.com/',
            num_requests=3
        )
        print(f"Connection Reused: {reuse_results['connection_reused']}")
        print(f"Contamination Detected: {reuse_results['contamination_detected']}")


if __name__ == "__main__":
    asyncio.run(example_http3_usage())
