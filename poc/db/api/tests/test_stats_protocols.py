import unittest

from app.stats.repository import (
    _protocol_distribution_from_counts,
    _protocol_segments_from_counts,
)


class ProtocolStatsTests(unittest.TestCase):
    def test_flat_distribution_excludes_network_protocols(self):
        distribution = _protocol_distribution_from_counts(
            {
                "ip": 10,
                "ipv6": 4,
                "tcp": 7,
                "udp": 3,
                "websocket": 2,
            }
        )

        self.assertEqual([row["name"] for row in distribution], ["TCP", "UDP", "WebSocket"])

    def test_protocol_segments_are_zero_filled_and_include_other(self):
        segments = _protocol_segments_from_counts(
            {
                "tcp": 5,
                "tls": 3,
                "http": 2,
                "websocket": 1,
            },
            other_application_count=4,
        )

        by_name = {segment["name"]: segment["protocols"] for segment in segments}

        self.assertEqual(
            by_name["Transport"],
            [{"name": "UDP", "count": 0}, {"name": "TCP", "count": 5}],
        )
        self.assertEqual(
            by_name["Application data"],
            [
                {"name": "HTTP", "count": 2},
                {"name": "WebSocket", "count": 1},
                {"name": "Other", "count": 4},
            ],
        )


if __name__ == "__main__":
    unittest.main()
