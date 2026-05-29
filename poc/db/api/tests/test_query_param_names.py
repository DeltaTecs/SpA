import unittest

from app.http_parsing import query_param_names


class QueryParamNamesTests(unittest.TestCase):
    def test_no_query_string(self):
        self.assertEqual(query_param_names("/api/v1/users"), [])

    def test_none_and_empty(self):
        self.assertEqual(query_param_names(None), [])
        self.assertEqual(query_param_names(""), [])

    def test_single_param(self):
        self.assertEqual(query_param_names("/search?q=hello"), ["q"])

    def test_sorted_and_deduped(self):
        self.assertEqual(query_param_names("/search?q=1&page=2&q=3"), ["page", "q"])

    def test_flag_without_value(self):
        self.assertEqual(query_param_names("/x?debug"), ["debug"])

    def test_fragment_is_ignored(self):
        self.assertEqual(query_param_names("/x?a=1&b=2#section"), ["a", "b"])

    def test_empty_query(self):
        self.assertEqual(query_param_names("/x?"), [])


if __name__ == "__main__":
    unittest.main()
