from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from proxyserver.config import ConfigStore
from proxyserver.mitm_addon import UserAgentProxyAddon


class _FakeClient:
    peername = ("127.0.0.1", 50000)


class _FakeRequest:
    def __init__(self) -> None:
        self.headers = {"User-Agent": "original-agent"}
        self.method = "GET"
        self.pretty_url = "https://example.test/path"


class _FakeFlow:
    def __init__(self) -> None:
        self.client_conn = _FakeClient()
        self.request = _FakeRequest()


class ConfigReloadTests(unittest.TestCase):
    def test_reload_on_read_observes_updates_from_another_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = str(Path(directory) / "proxy_config.json")
            reader = ConfigStore(config_path, reload_on_read=True)
            writer = ConfigStore(config_path)

            writer.update_from({"user_agent": "UpdatedAgent/12345"})

            self.assertEqual(reader.get().user_agent, "UpdatedAgent/12345")


class MitmAddonTests(unittest.TestCase):
    def test_request_hook_replaces_user_agent_from_config_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            config_path = str(Path(directory) / "proxy_config.json")
            writer = ConfigStore(config_path)
            writer.update_from({"user_agent": "MitmAgent/1"})
            addon = UserAgentProxyAddon(config_path)

            first_flow = _FakeFlow()
            addon.request(first_flow)
            self.assertEqual(first_flow.request.headers["User-Agent"], "MitmAgent/1")

            writer.update_from({"user_agent": "MitmAgent/2-longer"})
            second_flow = _FakeFlow()
            addon.request(second_flow)
            self.assertEqual(second_flow.request.headers["User-Agent"], "MitmAgent/2-longer")


if __name__ == "__main__":
    unittest.main()
