import unittest

from app.stats.repository import build_endpoint_tree


def _find(nodes, name):
    return next(n for n in nodes if n["name"] == name)


class EndpointTreeTests(unittest.TestCase):
    def test_builds_ip_host_path_hierarchy_with_counts(self):
        rows = [
            ("192.168.0.10", "GET /api/v1/users HTTP/1.1\r\nHost: api.example.com\r\n"),
            ("192.168.0.10", "GET /api/v1/login HTTP/1.1\r\nHost: api.example.com\r\n"),
            ("192.168.0.10", "GET /api/v1/users HTTP/1.1\r\nHost: api.example.com\r\n"),
        ]
        tree = build_endpoint_tree(rows)

        ip = _find(tree, "192.168.0.10")
        self.assertEqual(ip["type"], "ip")
        self.assertEqual(ip["count"], 3)

        host = _find(ip["children"], "api.example.com")
        self.assertEqual(host["type"], "host")
        self.assertEqual(host["count"], 3)

        api = _find(host["children"], "/api")
        self.assertEqual(api["count"], 3)
        v1 = _find(api["children"], "/v1")
        self.assertEqual(v1["count"], 3)
        # Two distinct leaves under /api/v1 with their own counts.
        users = _find(v1["children"], "/users")
        self.assertEqual(users["count"], 2)
        login = _find(v1["children"], "/login")
        self.assertEqual(login["count"], 1)

    def test_skips_non_requests(self):
        rows = [("10.0.0.1", "HTTP/1.1 200 OK\r\n"), ("10.0.0.1", None)]
        self.assertEqual(build_endpoint_tree(rows), [])

    def test_children_sorted_by_count_desc(self):
        rows = [
            ("1.1.1.1", "GET /a HTTP/1.1\r\nHost: h\r\n"),
            ("1.1.1.1", "GET /b HTTP/1.1\r\nHost: h\r\n"),
            ("1.1.1.1", "GET /b HTTP/1.1\r\nHost: h\r\n"),
        ]
        tree = build_endpoint_tree(rows)
        host = _find(tree, "1.1.1.1")["children"][0]
        names = [c["name"] for c in host["children"]]
        self.assertEqual(names[0], "/b")  # higher count first


if __name__ == "__main__":
    unittest.main()
