#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
packet_analyzer.py

Analyze network packets using LangChain and a local LLM (Ollama) to group
them into application-specific events.

Usage:
    python packet_analyzer.py --recording-id 1 \
        --db-host localhost --db-port 5432 --db-name main \
        --db-user appuser --db-password appuser_password \
        [--model llama3.2:3b-instruct-q4_K_M] [--ollama-host http://localhost:11434]
"""
from __future__ import annotations

import argparse
import logging
import re
import sys
import time
from typing import Dict, List, Optional, Tuple, Any

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
except ImportError:
    raise ImportError("psycopg2-binary is required. Install with: pip install psycopg2-binary")

try:
    from langchain_ollama import OllamaLLM
    from langchain_core.prompts import PromptTemplate
    from langchain_core.output_parsers import StrOutputParser
except ImportError:
    raise ImportError("langchain packages are required. Install with: pip install langchain langchain-ollama langchain-community")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# Database Manager
# ============================================================================

class DatabaseManager:
    """Manage database connections and operations for packet analysis."""
    
    def __init__(self, host: str, port: int, database: str, user: str, password: str):
        """
        Initialize the DatabaseManager.

        Args:
            host: Database host.
            port: Database port.
            database: Database name.
            user: Database user.
            password: Database password.
        """
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.conn = None
        self._protocol_cache: Dict[int, str] = {}
    
    def connect(self):
        """Establish database connection."""
        try:
            self.conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                database=self.database,
                user=self.user,
                password=self.password
            )
            logger.info(f"Connected to database {self.database} on {self.host}:{self.port}")
            self._load_protocol_cache()
        except psycopg2.Error as e:
            logger.error(f"Failed to connect to database: {e}")
            raise
    
    def disconnect(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            logger.info("Disconnected from database")
    
    def _load_protocol_cache(self):
        """Load protocol names into cache."""
        with self.conn.cursor() as cursor:
            cursor.execute("SELECT protocol_id, name FROM protocol")
            self._protocol_cache = {row[0]: row[1] for row in cursor.fetchall()}
    
    def get_protocol_name(self, protocol_id: int) -> str:
        """Get protocol name by ID."""
        return self._protocol_cache.get(protocol_id, f"Unknown({protocol_id})")
    
    def get_packets_for_recording(self, recording_id: int) -> List[Dict]:
        """
        Fetch all packets for a recording with their header information.
        
        Args:
            recording_id: The recording ID to query.
            
        Returns:
            List of packet dictionaries with all relevant data.
        """
        with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT 
                    p.packet_id,
                    p.recording_id,
                    p.conversation_id,
                    p.from_local,
                    p.timestamp,
                    p.number,
                    p.protocol_ids,
                    p.clear_application_payload,
                    p.entropy
                FROM packet p
                WHERE p.recording_id = %s
                ORDER BY p.number ASC
            """, (recording_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_packet_headers(self, packet_id: int) -> Dict[str, Any]:
        """
        Fetch all header information for a packet.
        
        Args:
            packet_id: The packet ID.
            
        Returns:
            Dictionary with ip, tcp, udp, and http headers if present.
        """
        headers = {
            'ip': None,
            'tcp': None,
            'udp': None,
            'http': None
        }
        
        with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
            # Get IP header
            cursor.execute("""
                SELECT ih.src_addr, ih.dst_addr
                FROM ip_header_information ih
                JOIN packet_header_information phi ON ih.header_information_id = phi.header_information_id
                WHERE phi.packet_id = %s
            """, (packet_id,))
            row = cursor.fetchone()
            if row:
                headers['ip'] = dict(row)
            
            # Get TCP header
            cursor.execute("""
                SELECT th.src_port, th.dst_port, th.length
                FROM tcp_header_information th
                JOIN packet_header_information phi ON th.header_information_id = phi.header_information_id
                WHERE phi.packet_id = %s
            """, (packet_id,))
            row = cursor.fetchone()
            if row:
                headers['tcp'] = dict(row)
            
            # Get UDP header
            cursor.execute("""
                SELECT uh.src_port, uh.dst_port, uh.length
                FROM udp_header_information uh
                JOIN packet_header_information phi ON uh.header_information_id = phi.header_information_id
                WHERE phi.packet_id = %s
            """, (packet_id,))
            row = cursor.fetchone()
            if row:
                headers['udp'] = dict(row)
            
            # Get HTTP header
            cursor.execute("""
                SELECT hh.text_header, hh.stream_id, hh.version
                FROM http_header_information hh
                JOIN packet_header_information phi ON hh.header_information_id = phi.header_information_id
                WHERE phi.packet_id = %s
            """, (packet_id,))
            row = cursor.fetchone()
            if row:
                headers['http'] = dict(row)
        
        return headers
    
    def get_events_for_recording(self, recording_id: int) -> List[Dict]:
        """
        Fetch all events that are associated with packets in the recording.
        
        Args:
            recording_id: The recording ID.
            
        Returns:
            List of event dictionaries.
        """
        with self.conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
                SELECT DISTINCT e.event_id, e.description, e.start_timestamp, e.end_timestamp
                FROM event e
                JOIN packet_event pe ON e.event_id = pe.event_id
                JOIN packet p ON pe.packet_id = p.packet_id
                WHERE p.recording_id = %s
                ORDER BY e.event_id
            """, (recording_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def create_event(self, description: str, timestamp: int) -> int:
        """
        Create a new event.
        
        Args:
            description: Event description.
            timestamp: Event timestamp.
            
        Returns:
            The created event ID.
        """
        with self.conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO event (description, start_timestamp, end_timestamp)
                VALUES (%s, %s, %s)
                RETURNING event_id
            """, (description, timestamp, timestamp))
            event_id = cursor.fetchone()[0]
            self.conn.commit()
            logger.info(f"Created new event {event_id}: {description}")
            return event_id
    
    def update_event_timestamps(self, event_id: int, timestamp: int):
        """
        Update event timestamps to include a new timestamp.
        
        Args:
            event_id: The event ID.
            timestamp: The timestamp to include.
        """
        with self.conn.cursor() as cursor:
            cursor.execute("""
                UPDATE event 
                SET start_timestamp = LEAST(start_timestamp, %s),
                    end_timestamp = GREATEST(end_timestamp, %s)
                WHERE event_id = %s
            """, (timestamp, timestamp, event_id))
            self.conn.commit()
    
    def assign_packet_to_event(self, packet_id: int, event_id: int):
        """
        Assign a packet to an event.
        
        Args:
            packet_id: The packet ID.
            event_id: The event ID.
        """
        with self.conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO packet_event (packet_id, event_id)
                VALUES (%s, %s)
                ON CONFLICT (packet_id, event_id) DO NOTHING
            """, (packet_id, event_id))
            self.conn.commit()


# ============================================================================
# LLM Analyzer
# ============================================================================

class PacketAnalyzer:
    """Analyze packets using LangChain and Ollama."""
    
    # Prompt template for packet analysis
    PROMPT_TEMPLATE = """Given the network packet payload below, assign the packet to an application-specific data exchange (here 'event'). For instance, assign HTTP request and response that feature username and password to a login event. If no event fits, exclaim the creation of a new one.

Answer ONLY with one of these formats:
- If assigning to an existing event: EVENT_ID:<id>
- If creating a new event: NEW_EVENT:<short description>

Do not include any other text in your response.

Packet Information:
- Payload (hex): {payload_hex}
- Protocol Layers: {layers}
- Stream (connection): {stream}
- Entropy (0-1): {entropy}

Existing Events:
{events}

Your response:"""

    def __init__(self, model: str = "llama3.2:3b-instruct-q4_K_M", ollama_host: str = "http://localhost:11434"):
        """
        Initialize the PacketAnalyzer.
        
        Args:
            model: Ollama model to use.
            ollama_host: Ollama server URL.
        """
        self.model_name = model
        self.ollama_host = ollama_host
        self.llm = None
        self.chain = None
    
    def initialize(self):
        """Initialize the LLM and chain."""
        logger.info(f"Initializing LLM with model: {self.model_name}")
        
        self.llm = OllamaLLM(
            model=self.model_name,
            base_url=self.ollama_host,
            temperature=0.1,  # Low temperature for more deterministic output
        )
        
        prompt = PromptTemplate(
            input_variables=["payload_hex", "layers", "stream", "entropy", "events"],
            template=self.PROMPT_TEMPLATE
        )
        
        self.chain = prompt | self.llm | StrOutputParser()
        logger.info("LLM initialized successfully")
    
    def format_payload_hex(self, payload: Optional[bytes], max_bytes: int = 256) -> str:
        """
        Format payload bytes as hex string with spaces.
        
        Args:
            payload: Raw payload bytes.
            max_bytes: Maximum number of bytes to include.
            
        Returns:
            Hex string with space-separated bytes.
        """
        if not payload:
            return "(empty)"
        
        # Convert memoryview to bytes if needed (psycopg2 returns memoryview for bytea)
        if isinstance(payload, memoryview):
            payload = bytes(payload)
        
        truncated = payload[:max_bytes]
        hex_str = ' '.join(f'{b:02x}' for b in truncated)
        
        if len(payload) > max_bytes:
            hex_str += f' ... ({len(payload) - max_bytes} more bytes)'
        
        return hex_str
    
    def format_layers(self, protocol_ids: List[int], db: DatabaseManager) -> str:
        """
        Format protocol layers as pipe-separated string.
        
        Args:
            protocol_ids: List of protocol IDs.
            db: Database manager for protocol name lookup.
            
        Returns:
            Pipe-separated protocol names.
        """
        if not protocol_ids:
            return "(unknown)"
        
        names = [db.get_protocol_name(pid) for pid in protocol_ids]
        return '|'.join(names)
    
    def format_stream(self, headers: Dict[str, Any]) -> str:
        """
        Format connection stream as 4-tuple.
        
        Args:
            headers: Packet headers dictionary.
            
        Returns:
            Connection string in format src_ip:src_port -> dst_ip:dst_port
        """
        ip = headers.get('ip')
        tcp = headers.get('tcp')
        udp = headers.get('udp')
        
        if not ip:
            return "(unknown)"
        
        src_ip = ip.get('src_addr', '?')
        dst_ip = ip.get('dst_addr', '?')
        
        if tcp:
            src_port = tcp.get('src_port', '?')
            dst_port = tcp.get('dst_port', '?')
            return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} (TCP)"
        elif udp:
            src_port = udp.get('src_port', '?')
            dst_port = udp.get('dst_port', '?')
            return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} (UDP)"
        else:
            return f"{src_ip} -> {dst_ip}"
    
    def format_events(self, events: List[Dict]) -> str:
        """
        Format events list for the prompt.
        
        Args:
            events: List of event dictionaries.
            
        Returns:
            Formatted events string.
        """
        if not events:
            return "(no existing events)"
        
        lines = []
        for event in events:
            lines.append(f"- ID: {event['event_id']}, Description: {event['description']}")
        return '\n'.join(lines)
    
    def should_skip_packet(self, packet: Dict, headers: Dict[str, Any]) -> bool:
        """
        Determine if a packet should be skipped.
        
        Skip packets that have no payload AND are not HTTP packets.
        
        Args:
            packet: Packet dictionary.
            headers: Packet headers.
            
        Returns:
            True if packet should be skipped.
        """
        has_payload = packet.get('clear_application_payload') is not None and len(packet.get('clear_application_payload', b'')) > 0
        is_http = headers.get('http') is not None
        
        if not has_payload and not is_http:
            return True
        
        return False
    
    def parse_llm_response(self, response: str) -> Tuple[Optional[int], Optional[str]]:
        """
        Parse LLM response to extract event ID or new event description.
        
        Args:
            response: Raw LLM response string.
            
        Returns:
            Tuple of (event_id, new_event_description). One will be None.
        """
        response = response.strip()
        
        # Try to match EVENT_ID:<id>
        event_id_match = re.search(r'EVENT_ID[:\s]*(\d+)', response, re.IGNORECASE)
        if event_id_match:
            return int(event_id_match.group(1)), None
        
        # Try to match NEW_EVENT:<description>
        new_event_match = re.search(r'NEW_EVENT[:\s]*(.+)', response, re.IGNORECASE)
        if new_event_match:
            return None, new_event_match.group(1).strip()
        
        # Fallback: if response is just a number, treat as event ID
        if response.isdigit():
            return int(response), None
        
        # Otherwise, treat entire response as new event description
        logger.warning(f"Could not parse LLM response, treating as new event: {response}")
        return None, response if response else "Unclassified network activity"
    
    def analyze_packet(self, packet: Dict, headers: Dict[str, Any], 
                       events: List[Dict], db: DatabaseManager) -> Tuple[Optional[int], Optional[str]]:
        """
        Analyze a single packet and return event assignment.
        
        Args:
            packet: Packet dictionary.
            headers: Packet headers.
            events: Current list of events.
            db: Database manager.
            
        Returns:
            Tuple of (event_id, new_event_description). One will be None.
        """
        payload_hex = self.format_payload_hex(packet.get('clear_application_payload'))
        layers = self.format_layers(packet.get('protocol_ids', []), db)
        stream = self.format_stream(headers)
        entropy = packet.get('entropy', 0) or 0
        entropy_normalized = entropy / 8.0  # Normalize to 0-1 range
        events_str = self.format_events(events)
        
        # Add HTTP header info to payload if present
        if headers.get('http') and headers['http'].get('text_header'):
            http_header = headers['http']['text_header']
            payload_hex = f"HTTP Header:\n{http_header}\n\nPayload: {payload_hex}"
        
        try:
            response = self.chain.invoke({
                "payload_hex": payload_hex,
                "layers": layers,
                "stream": stream,
                "entropy": f"{entropy_normalized:.3f}",
                "events": events_str
            })
            
            return self.parse_llm_response(response)
            
        except Exception as e:
            logger.error(f"LLM invocation failed for packet {packet['packet_id']}: {e}")
            return None, "Error during analysis"


# ============================================================================
# Main Analysis Function
# ============================================================================

def run_analysis(db: DatabaseManager, analyzer: PacketAnalyzer, recording_id: int):
    """
    Run the full analysis on a recording.
    
    Args:
        db: Database manager.
        analyzer: Packet analyzer.
        recording_id: Recording ID to analyze.
    """
    logger.info(f"Starting analysis for recording {recording_id}")
    
    # Fetch all packets for the recording
    packets = db.get_packets_for_recording(recording_id)
    logger.info(f"Found {len(packets)} packets for recording {recording_id}")
    
    if not packets:
        logger.warning("No packets found for recording")
        return
    
    # Track statistics
    stats = {
        'total': len(packets),
        'skipped': 0,
        'assigned': 0,
        'new_events': 0,
        'errors': 0
    }
    
    # Process each packet
    for i, packet in enumerate(packets):
        packet_id = packet['packet_id']
        packet_num = packet['number']
        
        # Get headers for this packet
        headers = db.get_packet_headers(packet_id)
        
        # Check if packet should be skipped
        if analyzer.should_skip_packet(packet, headers):
            stats['skipped'] += 1
            logger.debug(f"Skipping packet {packet_num} (no payload, not HTTP)")
            continue
        
        # Get current events for this recording
        events = db.get_events_for_recording(recording_id)
        
        # Analyze the packet
        logger.info(f"Analyzing packet {packet_num} ({i + 1}/{len(packets)})")
        event_id, new_event_desc = analyzer.analyze_packet(packet, headers, events, db)
        
        packet_timestamp = packet.get('timestamp', int(time.time() * 1000))
        
        if event_id is not None:
            # Assign to existing event
            db.assign_packet_to_event(packet_id, event_id)
            db.update_event_timestamps(event_id, packet_timestamp)
            stats['assigned'] += 1
            logger.info(f"  -> Assigned to existing event {event_id}")
        elif new_event_desc is not None:
            # Create new event
            new_event_id = db.create_event(new_event_desc, packet_timestamp)
            db.assign_packet_to_event(packet_id, new_event_id)
            stats['new_events'] += 1
            logger.info(f"  -> Created new event {new_event_id}: {new_event_desc}")
        else:
            stats['errors'] += 1
            logger.error(f"  -> Failed to classify packet {packet_num}")
    
    # Print summary
    logger.info("=" * 60)
    logger.info("Analysis Complete!")
    logger.info(f"  Total packets: {stats['total']}")
    logger.info(f"  Skipped (no payload/not HTTP): {stats['skipped']}")
    logger.info(f"  Assigned to existing events: {stats['assigned']}")
    logger.info(f"  New events created: {stats['new_events']}")
    logger.info(f"  Errors: {stats['errors']}")
    logger.info("=" * 60)


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Analyze network packets and group them into application events using LLM"
    )
    
    # Recording ID (required)
    parser.add_argument("-r", "--recording-id", type=int, required=True,
                        help="Recording ID to analyze")
    
    # Database connection arguments
    parser.add_argument("--db-host", default="localhost", help="Database host")
    parser.add_argument("--db-port", type=int, default=5432, help="Database port")
    parser.add_argument("--db-name", default="main", help="Database name")
    parser.add_argument("--db-user", default="appuser", help="Database user")
    parser.add_argument("--db-password", default="appuser_password", help="Database password")
    
    # LLM configuration
    parser.add_argument("--model", default="llama3.2:3b-instruct-q4_K_M",
                        help="Ollama model to use (default: llama3.2:3b-instruct-q4_K_M)")
    parser.add_argument("--ollama-host", default="http://localhost:11434",
                        help="Ollama server URL (default: http://localhost:11434)")
    
    # Verbosity
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="Increase verbosity (-v for DEBUG)")
    
    args = parser.parse_args()
    
    # Set log level based on verbosity
    if args.verbose >= 1:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Initialize database connection
    db = DatabaseManager(
        host=args.db_host,
        port=args.db_port,
        database=args.db_name,
        user=args.db_user,
        password=args.db_password
    )
    
    # Initialize packet analyzer
    analyzer = PacketAnalyzer(
        model=args.model,
        ollama_host=args.ollama_host
    )
    
    try:
        db.connect()
        analyzer.initialize()
        run_analysis(db, analyzer, args.recording_id)
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)
    finally:
        db.disconnect()


if __name__ == "__main__":
    main()
