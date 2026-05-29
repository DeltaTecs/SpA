import unittest

from app.packets.repository import _association_key


class AssociationKeyTests(unittest.TestCase):
    def test_conversation_only(self):
        # No HTTP -> grouped purely by conversation.
        self.assertEqual(_association_key(7, 100, http_count=0, stream_id=None), "conv:7")

    def test_conversation_with_http_stream(self):
        # HTTP stream present -> split per stream within the conversation.
        self.assertEqual(
            _association_key(7, 100, http_count=1, stream_id=3), "conv:7|stream:3"
        )

    def test_two_streams_same_conversation_differ(self):
        a = _association_key(7, 100, http_count=1, stream_id=3)
        b = _association_key(7, 101, http_count=1, stream_id=5)
        self.assertNotEqual(a, b)

    def test_http1_without_stream_id(self):
        # HTTP/1.1 has no stream id but should still mark HTTP presence.
        self.assertEqual(
            _association_key(7, 100, http_count=2, stream_id=None), "conv:7|http"
        )

    def test_no_conversation_falls_back_to_packet(self):
        self.assertEqual(_association_key(None, 100, http_count=0, stream_id=None), "pkt:100")


if __name__ == "__main__":
    unittest.main()
