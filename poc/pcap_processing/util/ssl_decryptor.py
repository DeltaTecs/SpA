import json
import logging
import os
import subprocess
import math
from typing import Dict, List, Optional, Set, Tuple, Any

logger = logging.getLogger(__name__)

class SSLKeylogDecryptor:
    """
    Handles decryption of TLS/QUIC traffic using tshark with SSLKEYLOGFILE format.
    Uses tshark to decrypt and decompress TLS/QUIC payloads.
    """
    def __init__(self, tshark_path: str, keylog_file: Optional[str] = None):
        """
        Initialize the decryptor with tshark path and optional keylog file.
        
        :param tshark_path: Path to the tshark executable.
        :param keylog_file: Path to the SSL keylog file.
        """
        self.tshark_path = tshark_path
        self.keylog_file = keylog_file
        self.decrypted_payloads = {}  # frame_number -> decrypted_payload
        self.packet_stack_info = {}   # frame_number -> stack info
        self.tshark_available = self._check_tshark()
        self._tshark_fields_cache: Optional[Set[str]] = None  # cache available field names
        
        if not self.tshark_available:
            logger.warning("tshark not found in PATH. Decryption will not be available.")
        elif keylog_file and os.path.exists(keylog_file):
            logger.info(f"Using keylog file: {keylog_file}")
    
    def _check_tshark(self) -> bool:
        """
        Verify if tshark is installed and executable.
        
        :return: True if tshark is available, False otherwise.
        """
        try:
            result = subprocess.run(
                [self.tshark_path, '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                logger.info(f"tshark found: {result.stdout.split()[1]}")
                return True
        except (subprocess.SubprocessError, FileNotFoundError, IndexError):
            pass
        return False
    
    def can_process(self) -> bool:
        """
        Check if tshark is available for processing.
        
        :return: True if tshark is available.
        """
        return self.tshark_available

    def can_decrypt(self) -> bool:
        """
        Check if both tshark and the keylog file are available for decryption.
        
        :return: True if decryption prerequisites are met.
        """
        return self.can_process() and self.keylog_file and os.path.exists(self.keylog_file)

    def _get_available_fields(self) -> Set[str]:
        """
        Query tshark for available fields to avoid runtime errors with unsupported fields.
        
        :return: A set of available tshark field names.
        """
        if self._tshark_fields_cache is not None:
            return self._tshark_fields_cache
        fields: Set[str] = set()
        if not self.tshark_available:
            self._tshark_fields_cache = fields
            return fields
        try:
            # -G fields lists all fields; parse first column before tab
            result = subprocess.run(
                [self.tshark_path, '-G', 'fields'],
                capture_output=True,
                text=True,
                timeout=15
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    # Each line: F	ab_name	...
                    parts = line.split('\t')
                    if len(parts) >= 3 and parts[0] == 'F':
                        fields.add(parts[2])
        except subprocess.SubprocessError:
            pass
        self._tshark_fields_cache = fields
        return fields

    def _reconstruct_headers(self, layers: Dict) -> Optional[bytes]:
        """
        Reconstruct HTTP/2 or HTTP/3 headers from tshark layers.
        
        :param layers: Dictionary of packet layers.
        :return: Reconstructed headers as bytes, or None.
        """
        # HTTP/3
        h3_names = layers.get('http3.headers.header.name') or layers.get('http3.header.header.name')
        h3_values = layers.get('http3.headers.header.value') or layers.get('http3.header.header.value')
        
        if h3_names and h3_values:
            if not isinstance(h3_names, list): h3_names = [h3_names]
            if not isinstance(h3_values, list): h3_values = [h3_values]
            
            min_len = min(len(h3_names), len(h3_values))
            if min_len > 0:
                lines = []
                for i in range(min_len):
                    lines.append(f"{h3_names[i]}: {h3_values[i]}")
                return "\r\n".join(lines).encode('utf-8')
        
        # HTTP/2
        h2_names = layers.get('http2.header.name')
        h2_values = layers.get('http2.header.value')
        
        if h2_names and h2_values:
            if not isinstance(h2_names, list): h2_names = [h2_names]
            if not isinstance(h2_values, list): h2_values = [h2_values]
            
            min_len = min(len(h2_names), len(h2_values))
            if min_len > 0:
                lines = []
                for i in range(min_len):
                    lines.append(f"{h2_names[i]}: {h2_values[i]}")
                return "\r\n".join(lines).encode('utf-8')

        return None

    def _reconstruct_http1(self, layers: Dict) -> Optional[Tuple[bytes, bytes, int]]:
        """
        Reconstruct HTTP/1.1 request/response from tshark fields.
        
        :param layers: Dictionary of packet layers.
        :return: Tuple of (header_bytes, body_bytes, version) or None.
        """
        # Helper to convert body to bytes
        def to_bytes(val):
            if not val: return b""
            if isinstance(val, bytes): return val
            if isinstance(val, list):
                return b"".join(to_bytes(v) for v in val)
            try:
                return bytes.fromhex(val.replace(':', ''))
            except ValueError:
                return val.encode('utf-8', errors='ignore')

        # Helper to get string from potential list
        def to_str(val):
            if isinstance(val, list):
                return " ".join(str(v) for v in val)
            return str(val) if val is not None else ""

        # Check for Response
        if 'http.response.version' in layers:
            version = to_str(layers.get('http.response.version', ''))
            code = to_str(layers.get('http.response.code', ''))
            phrase = to_str(layers.get('http.response.phrase', ''))
            status_line = f"{version} {code} {phrase}\r\n"
            
            headers = layers.get('http.response.line', [])
            if isinstance(headers, str): headers = [headers]
            
            body = layers.get('http.file_data') or layers.get('http.data')
            body_bytes = to_bytes(body)
            
            header_bytes = status_line.encode('utf-8') + "".join(headers).encode('utf-8')
            return header_bytes, body_bytes, 1

        # Check for Request
        if 'http.request.method' in layers:
            method = to_str(layers.get('http.request.method', ''))
            uri = to_str(layers.get('http.request.uri', ''))
            version = to_str(layers.get('http.request.version', ''))
            req_line = f"{method} {uri} {version}\r\n"
            
            headers = layers.get('http.request.line', [])
            if isinstance(headers, str): headers = [headers]
            
            body = layers.get('http.file_data') or layers.get('http.data')
            body_bytes = to_bytes(body)

            header_bytes = req_line.encode('utf-8') + "".join(headers).encode('utf-8')
            return header_bytes, body_bytes, 1
            
        return None

    def _extract_http_body(self, layers: Dict) -> List[Tuple[bytes, Optional[str], int]]:
        """
        Extract HTTP/2 or HTTP/3 body data from layers.
        
        :param layers: Dictionary of packet layers.
        :return: List of (payload, stream_id, version) tuples.
        """
        results = []
        
        def to_bytes_safe(v):
            if isinstance(v, list):
                    return b"".join(to_bytes_safe(x) for x in v)
            try:
                return bytes.fromhex(v.replace(':', ''))
            except ValueError:
                return v.encode('utf-8', errors='ignore')

        # HTTP/2
        http2_val = layers.get('http2.data') or layers.get('http2.data.data')
        if http2_val:
            val = http2_val
            stream_ids = layers.get('http2.streamid', [])
            if not isinstance(stream_ids, list): stream_ids = [stream_ids]
            
            if isinstance(val, list):
                # Try to match with stream IDs
                # If lengths match, assume 1:1
                if len(val) == len(stream_ids):
                    for i, v in enumerate(val):
                        results.append((to_bytes_safe(v), str(stream_ids[i]), 2))
                else:
                    # If not matching, we can't reliably assign stream IDs
                    # Just add them with None
                    for v in val:
                        results.append((to_bytes_safe(v), None, 2))
            else:
                # Single value
                sid = str(stream_ids[0]) if stream_ids else None
                results.append((to_bytes_safe(val), sid, 2))
        
        # HTTP/3 (usually handled via QUIC stream data, but if http3.data is present)
        elif 'http3.data' in layers:
             val = layers['http3.data']
             # HTTP/3 stream ID is usually the QUIC stream ID
             stream_ids = layers.get('quic.stream.stream_id', [])
             if not isinstance(stream_ids, list): stream_ids = [stream_ids]

             if isinstance(val, list):
                if len(val) == len(stream_ids):
                    for i, v in enumerate(val):
                        results.append((to_bytes_safe(v), str(stream_ids[i]), 3))
                else:
                    for v in val:
                        results.append((to_bytes_safe(v), None, 3))
             else:
                sid = str(stream_ids[0]) if stream_ids else None
                results.append((to_bytes_safe(val), sid, 3))

        return results

    def _get_fallback_payload(self, layers: Dict) -> List[Tuple[bytes, str, Optional[str]]]:
        """
        Attempt to retrieve payload from various fallback fields (QUIC, TLS, WebSocket).
        
        :param layers: Dictionary of packet layers.
        :return: List of (payload_bytes, protocol_name, stream_id).
        """
        results = []
        
        # Helper to convert single value to bytes
        def to_bytes(val):
            if isinstance(val, bytes):
                return val
            if isinstance(val, list):
                return b"".join(to_bytes(v) for v in val)
            if val:
                try:
                    return bytes.fromhex(val.replace(':', ''))
                except ValueError:
                    return val.encode('utf-8', errors='ignore')
            return b""

        # WebSocket specific handling
        if 'websocket.payload.text' in layers:
             val = layers['websocket.payload.text']
             if isinstance(val, list):
                 for v in val:
                     results.append((to_bytes(v), 'websocket', None))
             else:
                 results.append((to_bytes(val), 'websocket', None))
             return results
        
        if 'websocket.payload.close.status_code' in layers:
             val = layers['websocket.payload.close.status_code']
             status_code = int(val[0] if isinstance(val, list) else val)
             payload = status_code.to_bytes(2, 'big')
             if 'websocket.payload.close.reason' in layers:
                 payload += to_bytes(layers['websocket.payload.close.reason'])
             results.append((payload, 'websocket', None))
             return results

        preference_order = [
            ('http3.frame_payload', 'http3'),  # HTTP/3 frame payload (decrypted)
            ('quic.stream_data', 'quic'),  # QUIC stream data
            ('websocket.payload', 'websocket'), # WebSocket payload
            ('tls.app_data', 'tls'),  # TLS Application Data
            ('data.data', 'data'), # Generic data (especially DTLS Application Data)
        ]

        for field_name, protocol in preference_order:
            if field_name in layers:
                field_val = layers[field_name]
                
                # WebSocket special handling for "1" flag
                if protocol == 'websocket':
                    is_flag = False
                    if isinstance(field_val, list):
                        if all(v == "1" for v in field_val): is_flag = True
                    elif field_val == "1":
                        is_flag = True
                    
                    if is_flag:
                        if 'data.data' in layers:
                            results.append((to_bytes(layers['data.data']), 'websocket', None))
                            return results
                        results.append((b"", 'websocket', None))
                        return results

                # QUIC stream ID handling
                stream_ids = []
                if protocol == 'quic' or protocol == 'http3':
                    stream_ids = layers.get('quic.stream.stream_id', [])
                    if not isinstance(stream_ids, list): stream_ids = [stream_ids]
                    
                    if not stream_ids and protocol == 'http3':
                         stream_ids = layers.get('http3.streamid', [])
                         if not isinstance(stream_ids, list): stream_ids = [stream_ids]

                if isinstance(field_val, list):
                    if (protocol == 'quic' or protocol == 'http3') and len(field_val) == len(stream_ids):
                        for i, v in enumerate(field_val):
                            results.append((to_bytes(v), protocol, str(stream_ids[i])))
                    else:
                        if protocol == 'quic' or protocol == 'http3':
                             for v in field_val:
                                 results.append((to_bytes(v), protocol, None))
                        else:
                             # For others, maybe concatenate?
                             results.append((b"".join(to_bytes(v) for v in field_val), protocol, None))
                    return results
                else:
                    sid = str(stream_ids[0]) if stream_ids and (protocol == 'quic' or protocol == 'http3') else None
                    results.append((to_bytes(field_val), protocol, sid))
                    return results
        return results

    def _calculate_entropy(self, data: bytes) -> float:
        """
        Calculate Shannon entropy of the byte data.
        
        :param data: The byte data to calculate entropy for.
        :return: The entropy value.
        """
        if not data:
            return 0.0
        
        # Count frequencies
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
            
        entropy = 0.0
        total_len = len(data)
        
        for count in counts:
            if count > 0:
                p_x = count / total_len
                entropy += - p_x * math.log2(p_x)
                
        return entropy

    def _process_packet_layers(self, layers: Dict) -> List[Dict[str, Any]]:
        """
        Process raw tshark layers to extract structured decrypted data.
        
        :param layers: Dictionary of packet layers.
        :return: List of dictionaries containing header, payload, protocol, and stream_id.
        """
        results = []
        
        reconstructed_headers = self._reconstruct_headers(layers)
        http1_parts = self._reconstruct_http1(layers)
        http_bodies = self._extract_http_body(layers)
        
        if http1_parts:
            payload = http1_parts[1]
            results.append({
                'header': http1_parts[0],
                'payload': payload,
                'protocol': 'http',
                'stream_id': None,
                'version': http1_parts[2]
            })
            return results

        # Combine headers and body if present
        if http_bodies:
            for payload, stream_id, version in http_bodies:               
                if payload is None and reconstructed_headers is None:
                    continue

                results.append({
                    'header': reconstructed_headers,
                    'payload': payload,
                    'protocol': 'http',
                    'stream_id': stream_id,
                    'version': version
                })
            return results
        
        if reconstructed_headers and not http_bodies:
             stream_id = None
             version = 1
             if 'quic.stream.stream_id' in layers:
                 sid = layers['quic.stream.stream_id']
                 stream_id = str(sid[0]) if isinstance(sid, list) else str(sid)
                 version = 3
             elif 'http2.streamid' in layers:
                 sid = layers['http2.streamid']
                 stream_id = str(sid[0]) if isinstance(sid, list) else str(sid)
                 version = 2

             results.append({
                'header': reconstructed_headers,
                'payload': None,
                'protocol': 'http',
                'stream_id': stream_id,
                'version': version
            })
             return results

        # Fallback for HTTP/2 frames without data or headers (e.g. control frames)
        if 'http2.streamid' in layers:
             sid = layers['http2.streamid']
             stream_id = str(sid[0]) if isinstance(sid, list) else str(sid)
             results.append({
                'header': None,
                'payload': None,
                'protocol': 'http',
                'stream_id': stream_id,
                'version': 2
            })
             return results

        
        fallback_payloads = self._get_fallback_payload(layers)
        if fallback_payloads:
            for payload, protocol, stream_id in fallback_payloads:
                version = None
                if protocol == 'http3':
                    version = 3
                elif protocol == 'quic':
                    version = 3
                
                results.append({
                    'header': None,
                    'payload': payload,
                    'protocol': protocol,
                    'stream_id': stream_id,
                    'version': version
                })
            return results
        
        return []

    def decrypt_pcap(self, pcap_file: str) -> Dict[int, List[Dict[str, Any]]]:
        """
        Process PCAP file using tshark to extract protocol stack and decrypt if keylog is available.
        
        :param pcap_file: Path to the PCAP file.
        :return: Dictionary mapping frame numbers to list of decrypted payload data.
        """
        if not self.can_process():
            logger.warning("Cannot process: tshark not available")
            return {}
        
        logger.info(f"Processing PCAP with tshark: {pcap_file}")
        
        try:
            # Decide which fields are actually available in this tshark build
            available = self._get_available_fields()
            requested_fields = [
                'frame.number',
                'frame.protocols',
                'ip.src', 'ip.dst', 'ipv6.src', 'ipv6.dst',
                'tcp.srcport', 'tcp.dstport', 'tcp.len',
                'udp.srcport', 'udp.dstport', 'udp.length',
                # TLS/DTLS decrypted application data (unparsed)
                'data.data',
                'http3.frame_payload',  # HTTP/3 decrypted payload
                # QUIC decrypted stream/application payload candidates (newer Wireshark builds)
                'quic.stream_data',
                'quic.payload',  # generic decrypted payload
                'quic.crypto.data',  # handshake crypto data (might contain early data)
                # HTTP/2 & HTTP/3 data (only include if present to avoid errors)
                'http2.data',
                'http2.data.data',
                'http2.header.name',
                'http2.header.value',
                'http3.data',
                # HTTP/3 Headers (to reconstruct uncompressed payload)
                'http3.headers.header.name',
                'http3.header.header.name',
                'http3.headers.header.value',
                'http3.header.header.value',
                # Stream IDs
                'http2.streamid',
                'quic.stream.stream_id',
                # HTTP/1.1 fields
                'http.response.version', 'http.response.code', 'http.response.phrase',
                'http.request.method', 'http.request.uri', 'http.request.version',
                'http.response.line', 'http.request.line',
                'http.file_data', 'http.data',
                # WebSocket
                'websocket.payload',
                'websocket.payload.text',
                'websocket.payload.close.status_code',
                'websocket.payload.close.reason'
            ]
            # Filter out unavailable fields (tshark errors if invalid -e fields are passed)
            filtered_fields = [f for f in requested_fields if f in available]
            if 'frame.number' not in filtered_fields:
                logger.error("tshark missing required field 'frame.number'; aborting decryption")
                return {}

            # Build tshark command
            cmd = [
                self.tshark_path,
                '-r', pcap_file,
                '-T', 'json'
            ]
            
            if self.keylog_file and os.path.exists(self.keylog_file):
                 cmd.extend(['-o', f'tls.keylog_file:{self.keylog_file}'])
            
            # Add fields
            cmd += sum((['-e', f] for f in filtered_fields), [])

            logger.info(f"tshark field selection ({len(filtered_fields)}): {', '.join(filtered_fields)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode != 0:
                logger.error(f"tshark failed: {result.stderr}")
                return {}
            
            # Parse JSON output
            decrypted_map = {}
            self.packet_stack_info = {} # Reset stack info

            try:
                packets = json.loads(result.stdout)
                for pkt in packets:
                    layers = pkt.get('_source', {}).get('layers', {})
                    frame_num = layers.get('frame.number')
                    
                    if not frame_num:
                        continue
                    
                    frame_num = int(frame_num[0]) if isinstance(frame_num, list) else int(frame_num)
                    
                    # Extract stack info
                    self.packet_stack_info[frame_num] = self._extract_stack_info(layers)

                    # Extract decrypted data
                    decrypted_data = self._process_packet_layers(layers)
                    
                    if decrypted_data:
                        decrypted_map[frame_num] = decrypted_data
                
                logger.info(f"Processed {len(packets)} packets")
                return decrypted_map
                
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse tshark JSON output: {e}")
                return {}
        
        except subprocess.TimeoutExpired:
            logger.error("tshark process timed out")
            return {}
        except Exception as e:
            logger.error(f"Error during processing: {e}")
            return {}

    def _extract_stack_info(self, layers: Dict) -> Dict[str, Any]:
        """Extract transport protocol header attributes from layers."""
        info = {}
        
        # Protocols
        protocols_str = layers.get('frame.protocols', '')
        if isinstance(protocols_str, list): protocols_str = protocols_str[0]
        info['protocols'] = protocols_str.split(':') if protocols_str else []
        
        # IP
        if 'ip.src' in layers:
            info['ip_src'] = layers['ip.src'][0] if isinstance(layers['ip.src'], list) else layers['ip.src']
            info['ip_dst'] = layers['ip.dst'][0] if isinstance(layers['ip.dst'], list) else layers['ip.dst']
            info['ip_version'] = 'IP'
        elif 'ipv6.src' in layers:
            info['ip_src'] = layers['ipv6.src'][0] if isinstance(layers['ipv6.src'], list) else layers['ipv6.src']
            info['ip_dst'] = layers['ipv6.dst'][0] if isinstance(layers['ipv6.dst'], list) else layers['ipv6.dst']
            info['ip_version'] = 'IPv6'
            
        # TCP
        if 'tcp.srcport' in layers:
            info['src_port'] = int(layers['tcp.srcport'][0]) if isinstance(layers['tcp.srcport'], list) else int(layers['tcp.srcport'])
            info['dst_port'] = int(layers['tcp.dstport'][0]) if isinstance(layers['tcp.dstport'], list) else int(layers['tcp.dstport'])
            info['tcp_len'] = int(layers['tcp.len'][0]) if isinstance(layers['tcp.len'], list) else int(layers['tcp.len'])
            
        # UDP
        if 'udp.srcport' in layers:
            info['src_port'] = int(layers['udp.srcport'][0]) if isinstance(layers['udp.srcport'], list) else int(layers['udp.srcport'])
            info['dst_port'] = int(layers['udp.dstport'][0]) if isinstance(layers['udp.dstport'], list) else int(layers['udp.dstport'])
            info['udp_len'] = int(layers['udp.length'][0]) if isinstance(layers['udp.length'], list) else int(layers['udp.length'])

        return info

    def get_packet_stack(self, frame_number: int) -> Optional[Dict[str, Any]]:
        return self.packet_stack_info.get(frame_number)

    
    def get_decrypted_payload(self, frame_number: int) -> Optional[List[Dict[str, Any]]]:
        """Get decrypted payload for a specific frame number."""
        return self.decrypted_payloads.get(frame_number)
