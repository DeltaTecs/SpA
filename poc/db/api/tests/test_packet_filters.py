import unittest

from app.packets.repository import PacketFilters, _build_where


class PacketFilterWhereTests(unittest.TestCase):
    def test_filters_non_empty_clear_payload(self):
        where, params = _build_where(PacketFilters(has_clear_payload=True))

        self.assertIn("OCTET_LENGTH(p.clear_application_payload)", where)
        self.assertIn("> 0", where)
        self.assertEqual(params, [])

    def test_filters_empty_clear_payload(self):
        where, params = _build_where(PacketFilters(has_clear_payload=False))

        self.assertIn("OCTET_LENGTH(p.clear_application_payload)", where)
        self.assertIn("= 0", where)
        self.assertEqual(params, [])

    def test_filters_non_empty_http_header_text(self):
        where, params = _build_where(PacketFilters(has_http_header_text=True))

        self.assertIn("EXISTS", where)
        self.assertIn("http_header_information", where)
        self.assertIn("BTRIM(hh_filter.text_header)", where)
        self.assertEqual(params, [])

    def test_filters_application_protocol(self):
        where, params = _build_where(PacketFilters(_app_protocol_id=13))

        self.assertIn("p.protocol_ids @> ARRAY[%s]::bigint[]", where)
        self.assertEqual(params, [13])

    def test_filters_other_application_protocols(self):
        where, params = _build_where(
            PacketFilters(
                _other_app_protocol_ids=(5, 6),
                _excluded_app_protocol_ids=(13, 14),
            )
        )

        self.assertIn("p.protocol_ids && ARRAY[%s, %s]::bigint[]", where)
        self.assertIn("NOT (p.protocol_ids && ARRAY[%s, %s]::bigint[])", where)
        self.assertEqual(params, [5, 6, 13, 14])


if __name__ == "__main__":
    unittest.main()
