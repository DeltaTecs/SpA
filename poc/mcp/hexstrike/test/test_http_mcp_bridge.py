from __future__ import annotations

import sys
import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path
from unittest import mock

from starlette.testclient import TestClient


def _load_bridge_module():
    local_script = Path(__file__).resolve().parents[1] / "http_mcp_bridge.py"
    installed_script = Path("/usr/local/bin/hexstrike-http-mcp")
    script = local_script if local_script.exists() else installed_script
    loader = SourceFileLoader("hexstrike_http_mcp_bridge", str(script))
    spec = spec_from_loader(loader.name, loader)
    if spec is None:  # pragma: no cover - defensive import guard
        raise RuntimeError(f"Could not load HexStrike HTTP MCP bridge from {script}")
    module = module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


bridge = _load_bridge_module()


class AdminStopRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = TestClient(bridge.app)

    def test_correct_token_invokes_stop_logic(self) -> None:
        result = {"message": "stopped"}
        with (
            mock.patch.object(bridge, "TOOLS_ADMIN_TOKEN", "secret"),
            mock.patch.object(bridge, "_stop_active_tools", return_value=result) as stop,
        ):
            response = self.client.post(
                "/admin/tools/stop",
                headers={"Authorization": "Bearer secret"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), result)
        stop.assert_called_once_with()

    def test_missing_token_returns_401_without_stopping(self) -> None:
        with (
            mock.patch.object(bridge, "TOOLS_ADMIN_TOKEN", "secret"),
            mock.patch.object(bridge, "_stop_active_tools") as stop,
        ):
            response = self.client.post("/admin/tools/stop")

        self.assertEqual(response.status_code, 401)
        stop.assert_not_called()

    def test_wrong_token_returns_401_without_stopping(self) -> None:
        with (
            mock.patch.object(bridge, "TOOLS_ADMIN_TOKEN", "secret"),
            mock.patch.object(bridge, "_stop_active_tools") as stop,
        ):
            response = self.client.post(
                "/admin/tools/stop",
                headers={"Authorization": "Bearer wrong"},
            )

        self.assertEqual(response.status_code, 401)
        stop.assert_not_called()


class ListManagedProcessPidsTests(unittest.TestCase):
    def test_reads_documented_process_list(self) -> None:
        with mock.patch.object(
            bridge,
            "_request_hexstrike_json",
            return_value={"active_processes": {"22": {}, "11": {}}},
        ) as request:
            self.assertEqual(bridge._list_hexstrike_managed_process_pids(), [11, 22])

        request.assert_called_once_with("/api/processes/list")

    def test_falls_back_to_dashboard_when_process_list_fails(self) -> None:
        with mock.patch.object(
            bridge,
            "_request_hexstrike_json",
            side_effect=[
                bridge.HexStrikeApiError("GET", "/api/processes/list", "serialization failed"),
                {"processes": [{"pid": 22}, {"pid": "11"}]},
            ],
        ) as request:
            self.assertEqual(bridge._list_hexstrike_managed_process_pids(), [11, 22])

        self.assertEqual(
            request.call_args_list,
            [
                mock.call("/api/processes/list"),
                mock.call("/api/processes/dashboard"),
            ],
        )


class StopActiveToolsTests(unittest.TestCase):
    def test_stops_wrappers_even_when_managed_process_discovery_fails(self) -> None:
        managed = {
            "found": 0,
            "stopped": [],
            "already_finished": [],
            "failed": [],
            "discovery_error": "backend unavailable",
        }
        stdio = {"stopped": 2, "message": "stopped wrappers"}
        with (
            mock.patch.object(bridge, "_stop_hexstrike_managed_processes", return_value=managed),
            mock.patch.object(bridge, "_stop_active_stdio_tools", return_value=stdio) as stop_stdio,
        ):
            result = bridge._stop_active_tools()

        stop_stdio.assert_called_once_with()
        self.assertEqual(result["managed_processes"], managed)
        self.assertEqual(result["mcp_subprocesses"], stdio)
        self.assertIn("Could not enumerate", result["message"])

    def test_reports_managed_process_outcomes(self) -> None:
        def terminate(pid: int) -> bool:
            if pid == 31:
                return True
            if pid == 32:
                return False
            raise RuntimeError("stop failed")

        with (
            mock.patch.object(
                bridge, "_list_hexstrike_managed_process_pids", return_value=[31, 32, 33]
            ),
            mock.patch.object(
                bridge,
                "_terminate_hexstrike_managed_process",
                side_effect=terminate,
            ),
        ):
            result = bridge._stop_hexstrike_managed_processes()

        self.assertEqual(result["found"], 3)
        self.assertEqual(result["stopped"], [31])
        self.assertEqual(result["already_finished"], [32])
        self.assertEqual(result["failed"], [{"pid": 33, "error": "stop failed"}])


if __name__ == "__main__":
    unittest.main()
