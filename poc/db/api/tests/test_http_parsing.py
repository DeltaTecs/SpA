import unittest

from app.http_parsing import parse_http_header, split_path_segments


class ParseHttpHeaderTests(unittest.TestCase):
    def test_http1_request_line_and_host(self):
        text = "GET /api/v1/users?page=2 HTTP/1.1\r\nHost: api.example.com\r\nAccept: */*\r\n"
        info = parse_http_header(text)
        self.assertTrue(info.is_request)
        self.assertEqual(info.method, "GET")
        self.assertEqual(info.path, "/api/v1/users?page=2")
        self.assertEqual(info.host, "api.example.com")

    def test_host_lookup_is_case_insensitive(self):
        info = parse_http_header("POST /login HTTP/1.1\nhost: auth.example.com\n")
        self.assertEqual(info.method, "POST")
        self.assertEqual(info.host, "auth.example.com")

    def test_http2_pseudo_headers(self):
        text = ":method: GET\n:scheme: https\n:authority: cdn.example.com\n:path: /static/app.js\n"
        info = parse_http_header(text)
        self.assertTrue(info.is_request)
        self.assertEqual(info.method, "GET")
        self.assertEqual(info.host, "cdn.example.com")
        self.assertEqual(info.path, "/static/app.js")

    def test_response_is_not_a_request(self):
        info = parse_http_header("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n")
        self.assertFalse(info.is_request)
        self.assertIsNone(info.path)
        self.assertFalse(info.is_usable)

    def test_empty_and_none(self):
        self.assertFalse(parse_http_header(None).is_request)
        self.assertFalse(parse_http_header("").is_request)
        self.assertFalse(parse_http_header("   \r\n  ").is_request)


class SplitPathSegmentsTests(unittest.TestCase):
    def test_basic_split(self):
        self.assertEqual(split_path_segments("/api/v1/users"), ["api", "v1", "users"])

    def test_strips_query_and_fragment(self):
        self.assertEqual(split_path_segments("/search?q=1#frag"), ["search"])

    def test_root_and_empty(self):
        self.assertEqual(split_path_segments("/"), [])
        self.assertEqual(split_path_segments(""), [])
        self.assertEqual(split_path_segments(None), [])


if __name__ == "__main__":
    unittest.main()
