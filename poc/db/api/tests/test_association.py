import unittest

from app.packets.repository import _association_key


class AssociationKeyTests(unittest.TestCase):
    def test_flow_tuple_only(self):
        self.assertEqual(
            _association_key(
                packet_id=100,
                transport_protocol="TCP",
                src_ip="10.0.0.2",
                src_port=49152,
                dst_ip="203.0.113.10",
                dst_port=443,
                stream_id=None,
            ),
            "flow:TCP|[10.0.0.2]:49152|[203.0.113.10]:443",
        )

    def test_reverse_flow_has_same_key(self):
        outbound = _association_key(
            packet_id=100,
            transport_protocol="TCP",
            src_ip="10.0.0.2",
            src_port=49152,
            dst_ip="203.0.113.10",
            dst_port=443,
            stream_id=None,
        )
        inbound = _association_key(
            packet_id=101,
            transport_protocol="TCP",
            src_ip="203.0.113.10",
            src_port=443,
            dst_ip="10.0.0.2",
            dst_port=49152,
            stream_id=None,
        )

        self.assertEqual(outbound, inbound)

    def test_http_stream_splits_same_flow(self):
        stream_three = _association_key(
            packet_id=100,
            transport_protocol="TCP",
            src_ip="10.0.0.2",
            src_port=49152,
            dst_ip="203.0.113.10",
            dst_port=443,
            stream_id=3,
        )
        stream_five = _association_key(
            packet_id=101,
            transport_protocol="TCP",
            src_ip="10.0.0.2",
            src_port=49152,
            dst_ip="203.0.113.10",
            dst_port=443,
            stream_id=5,
        )

        self.assertNotEqual(stream_three, stream_five)

    def test_http_without_stream_id_uses_flow_key(self):
        self.assertEqual(
            _association_key(
                packet_id=100,
                transport_protocol="TCP",
                src_ip="10.0.0.2",
                src_port=49152,
                dst_ip="203.0.113.10",
                dst_port=80,
                stream_id=None,
            ),
            "flow:TCP|[10.0.0.2]:49152|[203.0.113.10]:80",
        )

    def test_incomplete_flow_falls_back_to_packet(self):
        self.assertEqual(
            _association_key(
                packet_id=100,
                transport_protocol=None,
                src_ip="10.0.0.2",
                src_port=49152,
                dst_ip="203.0.113.10",
                dst_port=443,
                stream_id=None,
            ),
            "pkt:100",
        )


if __name__ == "__main__":
    unittest.main()
