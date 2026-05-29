import unittest

from app.exchanges.grouping import (
    EnrichedPacket,
    compile_conversations,
    compile_exchanges,
    compile_http_pairs,
)

LOCAL_IP = "10.0.0.2"
REMOTE_IP = "203.0.113.10"


def http_request(packet_id, path, *, timestamp=0, payload=20, src_port=49152, dst_port=80):
    return EnrichedPacket(
        packet_id=packet_id,
        from_local=True,
        timestamp=timestamp,
        number=packet_id,
        transport="TCP",
        src_ip=LOCAL_IP,
        src_port=src_port,
        dst_ip=REMOTE_IP,
        dst_port=dst_port,
        http_text=f"GET {path} HTTP/1.1\r\nHost: api.example.com\r\n",
        http_count=1,
        payload_length=payload,
        protocols=("TCP", "HTTP"),
    )


def http_response(packet_id, status, *, timestamp=1, src_port=49152, dst_port=80):
    return EnrichedPacket(
        packet_id=packet_id,
        from_local=False,
        timestamp=timestamp,
        number=packet_id,
        transport="TCP",
        src_ip=REMOTE_IP,
        src_port=dst_port,
        dst_ip=LOCAL_IP,
        dst_port=src_port,
        http_text=f"HTTP/1.1 {status} OK\r\n",
        http_count=1,
        payload_length=10,
        protocols=("TCP", "HTTP"),
    )


def payload_packet(packet_id, *, from_local=True, payload=100, transport="TCP",
                   src_ip=LOCAL_IP, src_port=51000, dst_ip=REMOTE_IP, dst_port=4433):
    return EnrichedPacket(
        packet_id=packet_id,
        from_local=from_local,
        timestamp=packet_id,
        number=packet_id,
        transport=transport,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        http_count=0,
        payload_length=payload,
        protocols=("TCP", "TLS"),
    )


class HttpPairTests(unittest.TestCase):
    def test_same_endpoint_and_params_collapse(self):
        packets = [http_request(1, "/a?x=1"), http_request(2, "/a?x=2", timestamp=5)]
        exchanges, _ = compile_http_pairs(packets)
        self.assertEqual(len(exchanges), 1)
        self.assertEqual(exchanges[0]["packet_count"], 2)
        self.assertEqual(exchanges[0]["representative_packet_ids"][0], 1)  # first request
        self.assertEqual(exchanges[0]["http"]["endpoint_path"], "/a")
        self.assertEqual(exchanges[0]["http"]["param_names"], ["x"])

    def test_distinct_endpoint_yields_distinct_exchange(self):
        exchanges, _ = compile_http_pairs([http_request(1, "/a"), http_request(2, "/b")])
        self.assertEqual(len(exchanges), 2)

    def test_distinct_param_set_yields_distinct_exchange(self):
        exchanges, _ = compile_http_pairs([http_request(1, "/a?x=1"), http_request(2, "/a?y=1")])
        self.assertEqual(len(exchanges), 2)

    def test_request_paired_with_following_response(self):
        exchanges, _ = compile_http_pairs(
            [http_request(1, "/a", timestamp=0), http_response(2, 200, timestamp=1)]
        )
        self.assertEqual(len(exchanges), 1)
        self.assertEqual(exchanges[0]["http"]["status_code"], 200)
        self.assertEqual(exchanges[0]["representative_packet_ids"], [1, 2])
        self.assertEqual(exchanges[0]["remote"], {"ip": REMOTE_IP, "port": 80})


class ConversationTests(unittest.TestCase):
    def test_grouping_is_direction_normalized(self):
        outbound = payload_packet(1, from_local=True)
        inbound = payload_packet(
            2, from_local=False, src_ip=REMOTE_IP, src_port=4433,
            dst_ip=LOCAL_IP, dst_port=51000,
        )
        exchanges = compile_conversations([outbound, inbound], http_flow_keys=set())
        self.assertEqual(len(exchanges), 1)
        self.assertEqual(exchanges[0]["packet_count"], 2)
        self.assertEqual(exchanges[0]["local"], {"ip": LOCAL_IP, "port": 51000})
        self.assertEqual(exchanges[0]["remote"], {"ip": REMOTE_IP, "port": 4433})

    def test_incomplete_tuple_skipped(self):
        no_transport = payload_packet(1, transport=None)
        self.assertEqual(compile_conversations([no_transport], http_flow_keys=set()), [])

    def test_packets_without_payload_skipped(self):
        empty = payload_packet(1, payload=0)
        self.assertEqual(compile_conversations([empty], http_flow_keys=set()), [])


class CompileExchangesTests(unittest.TestCase):
    def test_http_flow_excluded_from_conversations(self):
        # An HTTP request and a non-HTTP payload packet share the same 5-tuple.
        request = http_request(1, "/a", src_port=51000, dst_port=4433)
        same_flow_payload = payload_packet(2, src_port=51000, dst_port=4433)
        exchanges = compile_exchanges([request, same_flow_payload])
        kinds = [e["kind"] for e in exchanges]
        self.assertIn("http_pair", kinds)
        self.assertNotIn("conversation", kinds)

    def test_distinct_flow_conversation_kept(self):
        request = http_request(1, "/a", src_port=51000, dst_port=4433)
        other_flow = payload_packet(2, src_port=52000, dst_port=4444)
        exchanges = compile_exchanges([request, other_flow])
        kinds = sorted({e["kind"] for e in exchanges})
        self.assertEqual(kinds, ["conversation", "http_pair"])


if __name__ == "__main__":
    unittest.main()
