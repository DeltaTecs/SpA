from __future__ import annotations

import os
import random
import re
import sys
import types
import unittest
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import psycopg2


HERE = Path(__file__).resolve()
PROJECT_ROOT = HERE.parents[1]
SRC_DIR = PROJECT_ROOT / "src"
INIT_SQL_PATH = next(
    (
        parent / "db" / "init_db.sql"
        for parent in HERE.parents
        if (parent / "db" / "init_db.sql").exists()
    ),
    None,
)

sys.path.insert(0, str(SRC_DIR))


def _install_fastmcp_stub_if_needed() -> None:
    """Allow direct tool-function tests when the optional mcp package is absent."""

    try:
        import mcp.server.fastmcp  # noqa: F401
        import mcp.server.fastmcp.server  # noqa: F401
        return
    except ImportError:
        pass

    class FastMCP:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def tool(self, *args: Any, **kwargs: Any):
            def decorator(func):
                return func

            return decorator

        def run(self, *args: Any, **kwargs: Any) -> None:
            pass

    class TransportSecuritySettings:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

    mcp_module = types.ModuleType("mcp")
    server_module = types.ModuleType("mcp.server")
    fastmcp_module = types.ModuleType("mcp.server.fastmcp")
    fastmcp_server_module = types.ModuleType("mcp.server.fastmcp.server")

    fastmcp_module.FastMCP = FastMCP
    fastmcp_server_module.TransportSecuritySettings = TransportSecuritySettings
    server_module.fastmcp = fastmcp_module
    mcp_module.server = server_module

    sys.modules.setdefault("mcp", mcp_module)
    sys.modules.setdefault("mcp.server", server_module)
    sys.modules.setdefault("mcp.server.fastmcp", fastmcp_module)
    sys.modules.setdefault("mcp.server.fastmcp.server", fastmcp_server_module)


def _install_dotenv_stub_if_needed() -> None:
    try:
        import dotenv  # noqa: F401
        return
    except ImportError:
        pass

    dotenv_module = types.ModuleType("dotenv")
    dotenv_module.load_dotenv = lambda *args, **kwargs: False
    sys.modules.setdefault("dotenv", dotenv_module)


def _configure_db_env() -> None:
    if os.environ.get("DB_DSN"):
        return

    os.environ.setdefault("DB_HOST", "postgres")
    os.environ.setdefault("DB_PORT", "5432")
    os.environ.setdefault("DB_NAME", "main")
    os.environ.setdefault("DB_USER", "appuser")
    os.environ.setdefault("DB_PASSWORD", "appuser")


_configure_db_env()
_install_dotenv_stub_if_needed()
_install_fastmcp_stub_if_needed()

from packet_db_server.server import (  # noqa: E402
    assign_packet_to_event,
    conversation_packets,
    create_event,
    create_event_and_assign_packet,
    event_packets,
    events_for_recording,
    list_packet_ids,
    packet_info,
    packet_payload_hexdump,
    packets_in_time_window,
)


class TestPacketDbServerTools(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.token = uuid.uuid4().hex[:12]
        cls.rng = random.Random(cls.token)
        cls.header_ids: List[int] = []
        cls.packet_ids: List[int] = []
        cls.event_ids: List[int] = []
        cls.conversation_ids: List[int] = []
        cls.recording_id: int | None = None
        cls.other_recording_id: int | None = None

        cls.conn = cls._connect_db()
        cls.conn.autocommit = True

        try:
            with cls.conn.cursor() as cursor:
                cls._ensure_schema(cursor)
                cls.protocol_ids = cls._protocol_ids(cursor)
                cls._insert_fixture(cursor)
        except Exception:
            cls._cleanup_fixture(cls.conn)
            cls.conn.close()
            raise

    @classmethod
    def tearDownClass(cls) -> None:
        conn = getattr(cls, "conn", None)
        if conn is None:
            return

        cls._cleanup_fixture(conn)
        conn.close()

    @classmethod
    def _cleanup_fixture(cls, conn) -> None:
        with conn.cursor() as cursor:
            if cls.event_ids:
                cursor.execute(
                    "DELETE FROM packet_event WHERE event_id = ANY(%s::bigint[])",
                    (cls.event_ids,),
                )
                cursor.execute(
                    "DELETE FROM event WHERE event_id = ANY(%s::bigint[])",
                    (cls.event_ids,),
                )

            recording_ids = [
                rid
                for rid in [getattr(cls, "recording_id", None), getattr(cls, "other_recording_id", None)]
                if rid is not None
            ]
            if recording_ids:
                cursor.execute(
                    "DELETE FROM recording WHERE recording_id = ANY(%s::bigint[])",
                    (recording_ids,),
                )

            if cls.conversation_ids:
                cursor.execute(
                    "DELETE FROM conversation WHERE conversation_id = ANY(%s::bigint[])",
                    (cls.conversation_ids,),
                )

            if cls.header_ids:
                for table in (
                    "ip_header_information",
                    "tcp_header_information",
                    "udp_header_information",
                    "http_header_information",
                    "header_information",
                ):
                    cursor.execute(
                        f"DELETE FROM {table} WHERE header_information_id = ANY(%s::bigint[])",
                        (cls.header_ids,),
                    )

    @staticmethod
    def _connect_db():
        dsn = os.environ.get("DB_DSN")
        if dsn:
            return psycopg2.connect(dsn)

        return psycopg2.connect(
            host=os.environ["DB_HOST"],
            port=os.environ["DB_PORT"],
            dbname=os.environ["DB_NAME"],
            user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"],
        )

    @classmethod
    def _ensure_schema(cls, cursor) -> None:
        if INIT_SQL_PATH is not None:
            with open(INIT_SQL_PATH, "r", encoding="utf-8") as sql_file:
                cursor.execute(sql_file.read())
            return

        cursor.execute("SELECT to_regclass('public.packet')")
        if cursor.fetchone()[0] is None:
            raise RuntimeError(
                "Database schema is missing and init_db.sql was not available to the test runtime."
            )

    @staticmethod
    def _protocol_ids(cursor) -> Dict[str, int]:
        cursor.execute("SELECT protocol_id, name FROM protocol")
        return {name: protocol_id for protocol_id, name in cursor.fetchall()}

    @classmethod
    def _insert_fixture(cls, cursor) -> None:
        base_timestamp = cls.rng.randrange(1_700_000_000_000, 1_800_000_000_000)
        base_number = cls.rng.randrange(10_000, 90_000)
        cls.base_timestamp = base_timestamp

        cursor.execute(
            "INSERT INTO recording (name, timestamp) VALUES (%s, %s) RETURNING recording_id",
            (f"mcp-test-recording-{cls.token}", base_timestamp),
        )
        cls.recording_id = cursor.fetchone()[0]

        cursor.execute(
            "INSERT INTO recording (name, timestamp) VALUES (%s, %s) RETURNING recording_id",
            (f"mcp-test-other-recording-{cls.token}", base_timestamp + 10_000),
        )
        cls.other_recording_id = cursor.fetchone()[0]

        cursor.execute("INSERT INTO conversation DEFAULT VALUES RETURNING conversation_id")
        cls.primary_conversation_id = cursor.fetchone()[0]
        cursor.execute("INSERT INTO conversation DEFAULT VALUES RETURNING conversation_id")
        cls.secondary_conversation_id = cursor.fetchone()[0]
        cls.conversation_ids.extend(
            [cls.primary_conversation_id, cls.secondary_conversation_id]
        )

        local_ip = cls._random_private_ip()
        remote_ip = cls._random_documentation_ip()
        udp_remote_ip = cls._random_documentation_ip()

        cls.packets = {
            "request": cls._make_packet(
                cursor=cursor,
                recording_id=cls.recording_id,
                conversation_id=cls.primary_conversation_id,
                from_local=True,
                timestamp=base_timestamp,
                number=base_number,
                protocol_names=("IP", "TCP", "HTTP"),
                payload=f"alpha-payload-{cls.token}-{cls.rng.getrandbits(32):08x}".encode(
                    "ascii"
                ),
                entropy=cls.rng.random(),
                ip=(local_ip, remote_ip),
                transport=("tcp", cls._random_port(), 443),
                http_header=(
                    f"GET /mcp-test/{cls.token} HTTP/1.1\r\n"
                    f"Host: example-{cls.token}.test\r\n\r\n"
                ),
            ),
            "response": cls._make_packet(
                cursor=cursor,
                recording_id=cls.recording_id,
                conversation_id=cls.primary_conversation_id,
                from_local=False,
                timestamp=base_timestamp + 500,
                number=base_number + 1,
                protocol_names=("IP", "TCP", "HTTP"),
                payload=f"beta-payload-{cls.token}-{cls.rng.getrandbits(32):08x}".encode(
                    "ascii"
                ),
                entropy=cls.rng.random(),
                ip=(remote_ip, local_ip),
                transport=("tcp", 443, cls._random_port()),
                http_header=(
                    "HTTP/1.1 200 OK\r\n"
                    f"X-MCP-Test: {cls.token}\r\n\r\n"
                ),
            ),
            "datagram": cls._make_packet(
                cursor=cursor,
                recording_id=cls.recording_id,
                conversation_id=cls.secondary_conversation_id,
                from_local=True,
                timestamp=base_timestamp + 750,
                number=base_number + 2,
                protocol_names=("IP", "UDP"),
                payload=bytes(cls.rng.randrange(0, 256) for _ in range(24)),
                entropy=cls.rng.random(),
                ip=(local_ip, udp_remote_ip),
                transport=("udp", cls._random_port(), 53),
                http_header=None,
            ),
            "followup": cls._make_packet(
                cursor=cursor,
                recording_id=cls.recording_id,
                conversation_id=cls.primary_conversation_id,
                from_local=True,
                timestamp=base_timestamp + 1_000,
                number=base_number + 3,
                protocol_names=("IP", "TCP"),
                payload=f"gamma-payload-{cls.token}-{cls.rng.getrandbits(32):08x}".encode(
                    "ascii"
                ),
                entropy=cls.rng.random(),
                ip=(local_ip, remote_ip),
                transport=("tcp", cls._random_port(), 443),
                http_header=None,
            ),
            "other_recording": cls._make_packet(
                cursor=cursor,
                recording_id=cls.other_recording_id,
                conversation_id=cls.primary_conversation_id,
                from_local=True,
                timestamp=base_timestamp + 2_000,
                number=base_number + 4,
                protocol_names=("IP", "TCP"),
                payload=f"other-recording-{cls.token}".encode("ascii"),
                entropy=cls.rng.random(),
                ip=(local_ip, remote_ip),
                transport=("tcp", cls._random_port(), 443),
                http_header=None,
            ),
        }

    @classmethod
    def _make_packet(
        cls,
        *,
        cursor,
        recording_id: int,
        conversation_id: int,
        from_local: bool,
        timestamp: int,
        number: int,
        protocol_names: Iterable[str],
        payload: bytes,
        entropy: float,
        ip: Tuple[str, str],
        transport: Tuple[str, int, int],
        http_header: str | None,
    ) -> Dict[str, Any]:
        protocol_ids = [cls.protocol_ids[name] for name in protocol_names]

        cursor.execute(
            """
            INSERT INTO packet (
                recording_id,
                conversation_id,
                from_local,
                timestamp,
                number,
                protocol_ids,
                packet_bytes,
                clear_application_payload,
                entropy
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING packet_id
            """,
            (
                recording_id,
                conversation_id,
                from_local,
                timestamp,
                number,
                protocol_ids,
                psycopg2.Binary(payload),
                psycopg2.Binary(payload),
                entropy,
            ),
        )
        packet_id = cursor.fetchone()[0]
        cls.packet_ids.append(packet_id)

        src_ip, dst_ip = ip
        cls._insert_header(
            cursor,
            packet_id,
            cls.protocol_ids["IP"],
            "ip",
            {"src_addr": src_ip, "dst_addr": dst_ip},
        )

        transport_type, src_port, dst_port = transport
        cls._insert_header(
            cursor,
            packet_id,
            cls.protocol_ids[transport_type.upper()],
            transport_type,
            {
                "src_port": src_port,
                "dst_port": dst_port,
                "length": len(payload),
            },
        )

        if http_header is not None:
            cls._insert_header(
                cursor,
                packet_id,
                cls.protocol_ids["HTTP"],
                "http",
                {
                    "text_header": http_header,
                    "stream_id": cls.rng.randrange(1, 1_000),
                    "version": 1,
                },
            )

        return {
            "packet_id": packet_id,
            "recording_id": recording_id,
            "conversation_id": conversation_id,
            "from_local": from_local,
            "timestamp": timestamp,
            "number": number,
            "protocol_names": tuple(protocol_names),
            "payload": payload,
            "entropy": entropy,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "transport": transport_type.upper(),
            "src_port": src_port,
            "dst_port": dst_port,
            "http_header": http_header,
        }

    @classmethod
    def _insert_header(
        cls,
        cursor,
        packet_id: int,
        protocol_id: int,
        header_type: str,
        fields: Dict[str, Any],
    ) -> int:
        cursor.execute(
            "INSERT INTO header_information (protocol_id) VALUES (%s) RETURNING header_information_id",
            (protocol_id,),
        )
        header_id = cursor.fetchone()[0]
        cls.header_ids.append(header_id)

        if header_type == "ip":
            cursor.execute(
                """
                INSERT INTO ip_header_information (header_information_id, src_addr, dst_addr)
                VALUES (%s, %s, %s)
                """,
                (header_id, fields["src_addr"], fields["dst_addr"]),
            )
        elif header_type == "tcp":
            cursor.execute(
                """
                INSERT INTO tcp_header_information (
                    header_information_id,
                    src_port,
                    dst_port,
                    length
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    header_id,
                    fields["src_port"],
                    fields["dst_port"],
                    fields["length"],
                ),
            )
        elif header_type == "udp":
            cursor.execute(
                """
                INSERT INTO udp_header_information (
                    header_information_id,
                    src_port,
                    dst_port,
                    length
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    header_id,
                    fields["src_port"],
                    fields["dst_port"],
                    fields["length"],
                ),
            )
        elif header_type == "http":
            cursor.execute(
                """
                INSERT INTO http_header_information (
                    header_information_id,
                    text_header,
                    stream_id,
                    version
                )
                VALUES (%s, %s, %s, %s)
                """,
                (
                    header_id,
                    fields["text_header"],
                    fields["stream_id"],
                    fields["version"],
                ),
            )
        else:
            raise ValueError(f"Unsupported header_type {header_type!r}")

        cursor.execute(
            """
            INSERT INTO packet_header_information (packet_id, header_information_id)
            VALUES (%s, %s)
            """,
            (packet_id, header_id),
        )
        return header_id

    @classmethod
    def _random_private_ip(cls) -> str:
        return f"10.{cls.rng.randrange(1, 255)}.{cls.rng.randrange(0, 255)}.{cls.rng.randrange(1, 255)}"

    @classmethod
    def _random_documentation_ip(cls) -> str:
        return f"198.51.100.{cls.rng.randrange(1, 255)}"

    @classmethod
    def _random_port(cls) -> int:
        return cls.rng.randrange(10_000, 60_000)

    def test_packet_info_returns_packet_headers_and_payload_preview(self) -> None:
        packet = self.packets["request"]

        text = packet_info(packet["packet_id"])

        self.assertIn(f"packet_id: {packet['packet_id']}", text)
        self.assertIn(f"recording_id: {packet['recording_id']}", text)
        self.assertIn(f"packet number: {packet['number']}", text)
        self.assertIn(
            f"{packet['src_ip']}:{packet['src_port']} -> {packet['dst_ip']}:{packet['dst_port']} TCP",
            text,
        )
        self.assertIn(f"timestamp: {packet['timestamp']} ms since epoch", text)
        self.assertIn("timestamp offset: 0 ms since recording start", text)
        self.assertIn(f"conversation_id: {packet['conversation_id']}", text)
        self.assertIn("direction: outbound", text)
        self.assertIn("protocol stack: IP > TCP > HTTP", text)
        self.assertIn(f"payload length: {len(packet['payload'])} bytes", text)
        self.assertIn(f"tcp payload length: {len(packet['payload'])} bytes", text)
        self.assertIn("app protocol: HTTP", text)
        self.assertIn(packet["http_header"], text)
        self.assertIn("alpha-payload", text)

    def test_packet_payload_hexdump_returns_full_payload(self) -> None:
        packet = self.packets["response"]

        text = packet_payload_hexdump(packet["packet_id"])

        self.assertIn("00000000", text)
        self.assertIn("beta-payload", text)
        self.assertIn(packet["payload"].hex(" ")[:20], text)

    def test_list_packet_ids_returns_recording_packets_in_number_order(self) -> None:
        text = list_packet_ids(self.recording_id)

        expected_packets = [
            self.packets["request"],
            self.packets["response"],
            self.packets["datagram"],
            self.packets["followup"],
        ]
        self.assertIn("total: 4 packets", text)
        self.assertNotIn(f"packet_id:{self.packets['other_recording']['packet_id']}", text)

        positions = []
        for packet in expected_packets:
            line = (
                f"packet_id:{packet['packet_id']}  number:{packet['number']}  "
                f"timestamp:{packet['timestamp']}"
            )
            self.assertIn(line, text)
            positions.append(text.index(line))
        self.assertEqual(positions, sorted(positions))

    def test_conversation_packets_returns_window_around_current_packet(self) -> None:
        current = self.packets["response"]
        before = self.packets["request"]
        after = self.packets["followup"]
        unrelated = self.packets["datagram"]

        text = conversation_packets(
            self.primary_conversation_id,
            packet_id=current["packet_id"],
            before=1,
            after=1,
        )

        self.assertIn(f"=== packet_id:{before['packet_id']} ===", text)
        self.assertIn(f"=== packet_id:{current['packet_id']}  <-- current ===", text)
        self.assertIn(f"=== packet_id:{after['packet_id']} ===", text)
        self.assertNotIn(f"packet_id:{unrelated['packet_id']}", text)
        self.assertIn("beta-payload", text)

    def test_packets_in_time_window_accepts_recording_relative_offsets(self) -> None:
        included = [self.packets["response"], self.packets["datagram"]]
        excluded = [self.packets["request"], self.packets["followup"]]

        text = packets_in_time_window(
            self.recording_id,
            start_ms=400,
            end_ms=800,
            max_packets=10,
        )

        for packet in included:
            self.assertIn(f"=== packet_id:{packet['packet_id']} ===", text)
            self.assertIn(f"timestamp offset: {packet['timestamp'] - self.base_timestamp} ms", text)

        for packet in excluded:
            self.assertNotIn(f"packet_id:{packet['packet_id']}", text)

    def test_events_can_be_created_assigned_and_listed_for_recording(self) -> None:
        response = self.packets["response"]
        datagram = self.packets["datagram"]
        description = f"mcp-test-event-{self.token}-{self.rng.getrandbits(32):08x}"

        create_result = create_event(description)
        match = re.fullmatch(r"event_id:(\d+)", create_result)
        self.assertIsNotNone(match, create_result)
        event_id = int(match.group(1))
        self.event_ids.append(event_id)

        self.assertEqual("ok", assign_packet_to_event(response["packet_id"], event_id))
        self.assertEqual("ok", assign_packet_to_event(datagram["packet_id"], event_id))

        text = events_for_recording(self.recording_id)

        expected_start = min(response["timestamp"], datagram["timestamp"])
        expected_end = max(response["timestamp"], datagram["timestamp"])
        self.assertIn(f"event_id:{event_id}", text)
        self.assertIn(f"description:{description}", text)
        self.assertIn(f"start:{expected_start}", text)
        self.assertIn(f"end:{expected_end}", text)

        event_text = event_packets(event_id)
        self.assertIn(f"event_id:{event_id}", event_text)
        self.assertIn(f"description:{description}", event_text)
        self.assertIn("packets:2", event_text)
        self.assertIn(f"packet_id:{response['packet_id']}", event_text)
        self.assertIn(f"packet_id:{datagram['packet_id']}", event_text)
        self.assertNotIn(f"packet_id:{self.packets['request']['packet_id']}", event_text)

    def test_event_can_be_created_and_assigned_atomically(self) -> None:
        packet = self.packets["request"]
        description = f"mcp-test-atomic-event-{self.token}-{self.rng.getrandbits(32):08x}"

        create_result = create_event_and_assign_packet(packet["packet_id"], description)
        match = re.fullmatch(r"event_id:(\d+)", create_result)
        self.assertIsNotNone(match, create_result)
        event_id = int(match.group(1))
        self.event_ids.append(event_id)

        text = events_for_recording(self.recording_id)

        self.assertIn(f"event_id:{event_id}", text)
        self.assertIn(f"description:{description}", text)
        self.assertIn(f"start:{packet['timestamp']}", text)
        self.assertIn(f"end:{packet['timestamp']}", text)

    def test_missing_packet_returns_not_found_text(self) -> None:
        with self.conn.cursor() as cursor:
            cursor.execute("SELECT COALESCE(MAX(packet_id), 0) + 1000000000 FROM packet")
            missing_packet_id = cursor.fetchone()[0]

        self.assertEqual(
            f"packet_id {missing_packet_id} not found",
            packet_info(missing_packet_id),
        )
        self.assertEqual(
            f"packet_id {missing_packet_id} not found",
            packet_payload_hexdump(missing_packet_id),
        )
        self.assertEqual(
            f"packet_id {missing_packet_id} not found",
            assign_packet_to_event(missing_packet_id, 1),
        )
        self.assertEqual(
            f"packet_id {missing_packet_id} not found",
            create_event_and_assign_packet(missing_packet_id, f"missing-{self.token}"),
        )


if __name__ == "__main__":
    unittest.main()
