#!/usr/bin/env python3
"""
Monitor traffic and dump Android Emulator memory on TLS/DTLS/QUIC events.

This script mirrors vm_traffic_monitor.py's packet-trigger and hint-file
behavior, but targets the Android Studio emulator on Windows. It pauses the AVD
through adb, writes a full minidump of the qemu-system-* process, then resumes
the AVD.
"""

from __future__ import annotations

import argparse
import ctypes
from ctypes import wintypes
from dataclasses import dataclass
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import threading
import time
from typing import Iterable, Optional


QEMU_PROCESS_NAMES = {
    "qemu-system-x86_64.exe",
    "qemu-system-aarch64.exe",
}


@dataclass(frozen=True)
class FlowKey:
    proto: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int

    def reverse(self) -> "FlowKey":
        return FlowKey(
            self.proto,
            self.dst_ip,
            self.dst_port,
            self.src_ip,
            self.src_port,
        )

    def hint_connection(self) -> str:
        return (
            f"{self.proto} {self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port}"
        )


PERIODIC_HINT_FLOW = FlowKey("TCP", "0.0.0.0", 0, "0.0.0.0", 0)


@dataclass(frozen=True)
class EmulatorDevice:
    serial: str
    state: str
    details: str


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str


@dataclass(frozen=True)
class ScapyLayers:
    sniff: object
    IP: object
    IPv6: object
    TCP: object
    UDP: object
    Raw: object


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Monitor traffic and dump Android Studio emulator memory on "
            "TLS/DTLS/QUIC application-data events."
        )
    )
    parser.add_argument(
        "--ip",
        nargs="+",
        default=[],
        help=(
            "Target IP address(es) to listen for. Supports IPv4 and IPv6. "
            "If omitted, listen for any IP traffic on the interface."
        ),
    )
    parser.add_argument(
        "--interface",
        help="Network interface to listen on. Required unless --periodic is used.",
    )
    parser.add_argument(
        "--dump-dir",
        required=True,
        type=Path,
        help="Directory to save emulator memory dumps.",
    )
    parser.add_argument(
        "--hints",
        required=True,
        type=Path,
        help="Path to the hints .txt file.",
    )
    parser.add_argument(
        "--serial",
        help="ADB serial for the target emulator, for example emulator-5554.",
    )
    parser.add_argument(
        "--qemu-pid",
        type=int,
        help="PID of the qemu-system-* process to dump.",
    )
    parser.add_argument(
        "--adb",
        type=Path,
        help="Path to adb.exe. Defaults to PATH or common Android SDK locations.",
    )
    parser.add_argument(
        "--staging-dir",
        type=Path,
        help="Optional staging directory for dump writes before moving to dump-dir.",
    )
    parser.add_argument(
        "--app-data-packets",
        type=int,
        default=2,
        help="Number of application-data packets in a flow before dumping.",
    )
    parser.add_argument(
        "--periodic",
        type=int,
        metavar="MILLISECONDS",
        help=(
            "Dump emulator memory periodically at this interval instead of "
            "triggering on TLS/DTLS/QUIC traffic."
        ),
    )
    parser.add_argument(
        "--skip-pause",
        action="store_true",
        help="Dump without adb emu avd stop/start. Intended as a fallback only.",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Resolve adb, emulator serial, AVD status, and qemu PID, then exit.",
    )
    return parser.parse_args()


def load_scapy() -> ScapyLayers:
    try:
        from scapy.all import IP, IPv6, Raw, TCP, UDP, sniff
    except ImportError as exc:
        raise RuntimeError(
            "Scapy is required for packet capture. Install it with pip install scapy."
        ) from exc

    return ScapyLayers(sniff=sniff, IP=IP, IPv6=IPv6, TCP=TCP, UDP=UDP, Raw=Raw)


class AdbEmulatorController:
    def __init__(self, adb_path: Optional[Path], serial: Optional[str]) -> None:
        self.adb_path = self._resolve_adb(adb_path)
        self.requested_serial = serial
        self._serial: Optional[str] = None

    def ensure_serial(self) -> str:
        if self._serial:
            return self._serial

        if self.requested_serial:
            state = self._run_adb(["-s", self.requested_serial, "get-state"]).strip()
            if state != "device":
                raise RuntimeError(
                    f"ADB serial {self.requested_serial!r} is not ready: {state!r}"
                )
            self._serial = self.requested_serial
            return self._serial

        devices = [
            device
            for device in self.list_emulators()
            if device.state == "device" and device.serial.startswith("emulator-")
        ]
        if not devices:
            raise RuntimeError(
                "No running Android emulator found. Use --serial if adb lists one."
            )
        if len(devices) > 1:
            serials = ", ".join(device.serial for device in devices)
            raise RuntimeError(
                f"Multiple running emulators found ({serials}). Pass --serial."
            )

        self._serial = devices[0].serial
        return self._serial

    def list_emulators(self) -> list[EmulatorDevice]:
        output = self._run_adb(["devices", "-l"])
        devices: list[EmulatorDevice] = []
        for line in output.splitlines():
            line = line.strip()
            if not line or line.startswith("List of devices"):
                continue
            parts = line.split(maxsplit=2)
            if len(parts) < 2:
                continue
            serial, state = parts[0], parts[1]
            details = parts[2] if len(parts) > 2 else ""
            if serial.startswith("emulator-"):
                devices.append(EmulatorDevice(serial, state, details))
        return devices

    def ping(self) -> str:
        return self._emu(["ping"])

    def avd_name(self) -> str:
        lines = self._emu_lines(["avd", "name"])
        return lines[0] if lines else "<unknown>"

    def avd_status(self) -> str:
        lines = self._emu_lines(["avd", "status"])
        return lines[0] if lines else "<unknown>"

    def stop(self) -> None:
        self._emu(["avd", "stop"])

    def start(self) -> None:
        self._emu(["avd", "start"])

    def _emu_lines(self, args: list[str]) -> list[str]:
        return [
            line
            for line in self._emu(args).splitlines()
            if line.strip() and line.strip() != "OK"
        ]

    def _emu(self, args: list[str]) -> str:
        serial = self.ensure_serial()
        output = self._run_adb(["-s", serial, "emu", *args])
        if "KO:" in output:
            raise RuntimeError(output.strip())
        return output

    def _run_adb(self, args: list[str]) -> str:
        command = [str(self.adb_path), *args]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError as exc:
            raise RuntimeError(f"adb not found: {self.adb_path}") from exc

        if result.returncode != 0:
            detail = (result.stderr or result.stdout).strip()
            raise RuntimeError(f"Command failed: {' '.join(command)}\n{detail}")
        return result.stdout.replace("\r", "")

    @staticmethod
    def _resolve_adb(adb_path: Optional[Path]) -> Path:
        if adb_path:
            resolved = adb_path.expanduser()
            if resolved.exists():
                return resolved
            raise RuntimeError(f"adb path does not exist: {resolved}")

        found = shutil.which("adb")
        if found:
            return Path(found)

        candidates: list[Path] = []
        for env_name in ("ANDROID_HOME", "ANDROID_SDK_ROOT", "LOCALAPPDATA"):
            env_value = os.environ.get(env_name)
            if env_value:
                base = Path(env_value)
                if env_name == "LOCALAPPDATA":
                    candidates.append(
                        base / "Android" / "Sdk" / "platform-tools" / "adb.exe"
                    )
                else:
                    candidates.append(base / "platform-tools" / "adb.exe")

        candidates.append(
            Path.home()
            / "AppData"
            / "Local"
            / "Android"
            / "Sdk"
            / "platform-tools"
            / "adb.exe"
        )

        for candidate in candidates:
            if candidate.exists():
                return candidate

        raise RuntimeError(
            "adb not found. Pass --adb or add Android SDK platform-tools to PATH."
        )


class WindowsQemuProcessFinder:
    def __init__(self, qemu_pid: Optional[int]) -> None:
        self.qemu_pid = qemu_pid

    def find_pid(self) -> int:
        processes = list(self._iter_processes())

        if self.qemu_pid is not None:
            for process in processes:
                if process.pid == self.qemu_pid:
                    if process.name.lower() not in QEMU_PROCESS_NAMES:
                        raise RuntimeError(
                            f"PID {self.qemu_pid} is {process.name}, not qemu-system-*."
                        )
                    return process.pid
            raise RuntimeError(f"Configured --qemu-pid {self.qemu_pid} was not found.")

        candidates = [
            process
            for process in processes
            if process.name.lower() in QEMU_PROCESS_NAMES
        ]
        if not candidates:
            names = ", ".join(sorted(QEMU_PROCESS_NAMES))
            raise RuntimeError(f"No {names} process found. Pass --qemu-pid if needed.")
        if len(candidates) > 1:
            summary = ", ".join(f"{item.name}:{item.pid}" for item in candidates)
            raise RuntimeError(
                f"Multiple qemu-system processes found ({summary}). Pass --qemu-pid."
            )
        return candidates[0].pid

    def _iter_processes(self) -> Iterable[ProcessInfo]:
        if sys.platform != "win32":
            raise RuntimeError("Windows qemu process discovery is only available on Windows.")

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        class ProcessEntry32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
        kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
        kernel32.Process32FirstW.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessEntry32W),
        ]
        kernel32.Process32FirstW.restype = wintypes.BOOL
        kernel32.Process32NextW.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(ProcessEntry32W),
        ]
        kernel32.Process32NextW.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
        invalid_handle = ctypes.c_void_p(-1).value
        if snapshot == invalid_handle:
            _raise_last_error("CreateToolhelp32Snapshot failed")

        try:
            entry = ProcessEntry32W()
            entry.dwSize = ctypes.sizeof(ProcessEntry32W)

            first = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
            if not first:
                _raise_last_error("Process32FirstW failed")

            while True:
                yield ProcessInfo(pid=int(entry.th32ProcessID), name=entry.szExeFile)
                entry.dwSize = ctypes.sizeof(ProcessEntry32W)
                if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                    error = ctypes.get_last_error()
                    if error == 18:  # ERROR_NO_MORE_FILES
                        break
                    _raise_last_error("Process32NextW failed")
        finally:
            kernel32.CloseHandle(snapshot)


class WindowsMinidumpWriter:
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    PROCESS_DUP_HANDLE = 0x0040

    GENERIC_WRITE = 0x40000000
    CREATE_ALWAYS = 2
    FILE_ATTRIBUTE_NORMAL = 0x80

    MINIDUMP_WITH_FULL_MEMORY = 0x00000002
    MINIDUMP_WITH_HANDLE_DATA = 0x00000004
    MINIDUMP_WITH_UNLOADED_MODULES = 0x00000020
    MINIDUMP_WITH_FULL_MEMORY_INFO = 0x00000800
    MINIDUMP_WITH_THREAD_INFO = 0x00001000
    MINIDUMP_IGNORE_INACCESSIBLE_MEMORY = 0x00020000

    DEFAULT_DUMP_TYPE = (
        MINIDUMP_WITH_FULL_MEMORY
        | MINIDUMP_WITH_HANDLE_DATA
        | MINIDUMP_WITH_UNLOADED_MODULES
        | MINIDUMP_WITH_FULL_MEMORY_INFO
        | MINIDUMP_WITH_THREAD_INFO
        | MINIDUMP_IGNORE_INACCESSIBLE_MEMORY
    )

    def __init__(self, dump_type: int = DEFAULT_DUMP_TYPE) -> None:
        if sys.platform != "win32":
            raise RuntimeError("Windows minidump writing is only available on Windows.")
        self.dump_type = dump_type
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.dbghelp = ctypes.WinDLL("Dbghelp", use_last_error=True)
        self._configure_api()

    def write_dump(self, pid: int, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        process_handle = self.kernel32.OpenProcess(
            self.PROCESS_QUERY_INFORMATION | self.PROCESS_VM_READ | self.PROCESS_DUP_HANDLE,
            False,
            pid,
        )
        if not process_handle:
            _raise_last_error(
                f"OpenProcess failed for PID {pid}. Try an elevated shell if needed"
            )

        file_handle = self.kernel32.CreateFileW(
            str(output_path),
            self.GENERIC_WRITE,
            0,
            None,
            self.CREATE_ALWAYS,
            self.FILE_ATTRIBUTE_NORMAL,
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if file_handle == invalid_handle:
            self.kernel32.CloseHandle(process_handle)
            _raise_last_error(f"CreateFileW failed for {output_path}")

        try:
            ok = self.dbghelp.MiniDumpWriteDump(
                process_handle,
                pid,
                file_handle,
                self.dump_type,
                None,
                None,
                None,
            )
            if not ok:
                _raise_last_error(f"MiniDumpWriteDump failed for PID {pid}")
        finally:
            self.kernel32.CloseHandle(file_handle)
            self.kernel32.CloseHandle(process_handle)

    def _configure_api(self) -> None:
        self.kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.kernel32.OpenProcess.restype = wintypes.HANDLE
        self.kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self.kernel32.CreateFileW.restype = wintypes.HANDLE
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        self.kernel32.CloseHandle.restype = wintypes.BOOL

        self.dbghelp.MiniDumpWriteDump.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPVOID,
            wintypes.LPVOID,
            wintypes.LPVOID,
        ]
        self.dbghelp.MiniDumpWriteDump.restype = wintypes.BOOL


class DumpCoordinator:
    def __init__(
        self,
        controller: AdbEmulatorController,
        process_finder: WindowsQemuProcessFinder,
        dump_writer: WindowsMinidumpWriter,
        dump_dir: Path,
        hints_file: Path,
        staging_dir: Optional[Path],
        skip_pause: bool,
    ) -> None:
        self.controller = controller
        self.process_finder = process_finder
        self.dump_writer = dump_writer
        self.dump_dir = dump_dir
        self.hints_file = hints_file
        self.staging_dir = staging_dir
        self.skip_pause = skip_pause
        self.lock = threading.Lock()

    def prepare_outputs(self) -> None:
        self.dump_dir.mkdir(parents=True, exist_ok=True)
        if self.staging_dir:
            self.staging_dir.mkdir(parents=True, exist_ok=True)
        if self.hints_file.parent != Path("."):
            self.hints_file.parent.mkdir(parents=True, exist_ok=True)

    def perform_dump(self, flow_key: Optional[FlowKey], reason: str) -> None:
        with self.lock:
            dump_filename = f"{secrets.token_hex(6)}.dmp"
            staging_dir = self.staging_dir or self.dump_dir
            staging_path = staging_dir / dump_filename
            final_path = self.dump_dir / dump_filename
            start_time = time.time()
            paused = False

            trigger = flow_key.hint_connection() if flow_key else "periodic timer"
            print(f"[*] Triggered by {trigger} ({reason}).")
            print("[*] Starting Android Emulator memory dump...")

            try:
                pid = self.process_finder.find_pid()
                if not self.skip_pause:
                    self.controller.stop()
                    paused = True
                self.dump_writer.write_dump(pid, staging_path)
            except Exception as exc:
                print(f"[!] Failed to perform dump sequence: {exc}", file=sys.stderr)
                return
            finally:
                if paused:
                    try:
                        self.controller.start()
                    except Exception as exc:
                        print(f"[!] Failed to resume Android Emulator: {exc}", file=sys.stderr)

            duration = time.time() - start_time
            print(f"[+] Dump write completed in {duration:.2f} seconds.")

            try:
                if staging_path.resolve() != final_path.resolve():
                    shutil.move(str(staging_path), str(final_path))
                self._append_hint(start_time, dump_filename, flow_key, reason)
                print(f"[+] Dump saved to {final_path}")
            except Exception as exc:
                print(f"[!] Dump finalization failed: {exc}", file=sys.stderr)

    def _append_hint(
        self,
        start_time: float,
        dump_filename: str,
        flow_key: Optional[FlowKey],
        reason: str,
    ) -> None:
        hint_flow = flow_key or PERIODIC_HINT_FLOW
        timestamp_ms = int(start_time * 1000)
        hint_line = (
            f"Timestamp: {timestamp_ms} | File: {dump_filename} | "
            f"Connection: {hint_flow.hint_connection()} | Cause: {reason}\n"
        )
        with self.hints_file.open("a", encoding="utf-8") as handle:
            handle.write(hint_line)


class PeriodicDumpMonitor:
    def __init__(self, interval_ms: int, dump_coordinator: DumpCoordinator) -> None:
        self.interval_ms = interval_ms
        self.interval_seconds = interval_ms / 1000.0
        self.dump_coordinator = dump_coordinator

    def run(self) -> None:
        dump_count = 0
        print(f"Periodic mode: dumping every {self.interval_ms} ms.")
        print("Packet capture is disabled in periodic mode.")

        while True:
            dump_count += 1
            reason = f"Periodic Dump #{dump_count} ({self.interval_ms} ms interval)"
            self.dump_coordinator.perform_dump(None, reason)
            time.sleep(self.interval_seconds)


class TrafficMonitor:
    def __init__(
        self,
        target_ips: list[str],
        interface: str,
        app_data_packets: int,
        dump_coordinator: DumpCoordinator,
        layers: ScapyLayers,
    ) -> None:
        self.target_ips = target_ips
        self.interface = interface
        self.app_data_packets = app_data_packets
        self.dump_coordinator = dump_coordinator
        self.layers = layers
        self.processed_flows: set[FlowKey] = set()
        self.flow_app_data_packet_counts: dict[FlowKey, int] = {}

    def run(self) -> None:
        sniff_filter = None
        if self.target_ips:
            sniff_filter = " or ".join(f"host {ip}" for ip in self.target_ips)
            print(f"Listening for traffic from {', '.join(self.target_ips)}...")
        else:
            print("Listening for traffic from any IP...")

        print(f"Interface: {self.interface}")
        sniff_kwargs = {
            "prn": self.analyze_packet,
            "store": 0,
            "iface": self.interface,
        }
        if sniff_filter:
            sniff_kwargs["filter"] = sniff_filter
        self.layers.sniff(**sniff_kwargs)

    def analyze_packet(self, pkt: object) -> None:
        flow_key, payload = self._extract_flow_and_payload(pkt)
        if flow_key is None or not payload:
            return

        reverse_flow_key = flow_key.reverse()
        if flow_key in self.processed_flows or reverse_flow_key in self.processed_flows:
            return

        if not self._contains_application_data(flow_key.proto, payload):
            return

        count = self.flow_app_data_packet_counts.get(flow_key, 0) + 1
        self.flow_app_data_packet_counts[flow_key] = count
        if count != self.app_data_packets:
            return

        reason = f"Application Data Packet #{self.app_data_packets}"
        self.dump_coordinator.perform_dump(flow_key, reason)
        self.processed_flows.add(flow_key)
        self.processed_flows.add(reverse_flow_key)
        self.flow_app_data_packet_counts.pop(flow_key, None)
        self.flow_app_data_packet_counts.pop(reverse_flow_key, None)

    def _extract_flow_and_payload(self, pkt: object) -> tuple[Optional[FlowKey], bytes]:
        ip_layer = pkt.getlayer(self.layers.IP)
        ipv6_layer = pkt.getlayer(self.layers.IPv6)
        if ip_layer:
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
        elif ipv6_layer:
            src_ip = ipv6_layer.src
            dst_ip = ipv6_layer.dst
        else:
            return None, b""

        tcp_layer = pkt.getlayer(self.layers.TCP)
        udp_layer = pkt.getlayer(self.layers.UDP)
        raw_layer = pkt.getlayer(self.layers.Raw)
        payload = raw_layer.load if raw_layer else b""

        if tcp_layer:
            flow_key = FlowKey("TCP", src_ip, tcp_layer.sport, dst_ip, tcp_layer.dport)
            return flow_key, payload
        if udp_layer:
            flow_key = FlowKey("UDP", src_ip, udp_layer.sport, dst_ip, udp_layer.dport)
            return flow_key, payload

        return None, b""

    def _contains_application_data(self, proto: str, payload: bytes) -> bool:
        if proto == "TCP":
            return self._contains_tls_application_data(payload)
        if proto == "UDP":
            return self._contains_dtls_or_quic_application_data(payload)
        return False

    @staticmethod
    def _contains_tls_application_data(payload: bytes) -> bool:
        offset = 0
        while offset + 5 <= len(payload):
            content_type = payload[offset]
            length = int.from_bytes(payload[offset + 3 : offset + 5], byteorder="big")
            record_len = 5 + length
            if offset + record_len > len(payload):
                break
            if content_type == 23:
                return True
            offset += record_len
        return False

    @staticmethod
    def _contains_dtls_or_quic_application_data(payload: bytes) -> bool:
        if not payload:
            return False

        first_byte = payload[0]
        if 20 <= first_byte <= 25 and len(payload) >= 13:
            version = int.from_bytes(payload[1:3], byteorder="big")
            if version in (0xFEFF, 0xFEFD, 0xFEFC) and first_byte == 23:
                return True

        is_quic_long_header = (first_byte & 0x80) != 0
        return not is_quic_long_header


def _raise_last_error(message: str) -> None:
    error = ctypes.get_last_error()
    if error:
        raise OSError(error, f"{message}: {ctypes.FormatError(error)}")
    raise OSError(message)


def validate_environment(
    controller: AdbEmulatorController,
    process_finder: WindowsQemuProcessFinder,
) -> None:
    serial = controller.ensure_serial()
    avd_name = controller.avd_name()
    avd_status = controller.avd_status()
    qemu_pid = process_finder.find_pid()
    print(f"ADB:        {controller.adb_path}")
    print(f"Serial:     {serial}")
    print(f"AVD name:   {avd_name}")
    print(f"AVD status: {avd_status}")
    print(f"QEMU PID:   {qemu_pid}")


def main() -> int:
    args = parse_args()
    if args.app_data_packets < 1:
        print("Error: --app-data-packets must be at least 1.", file=sys.stderr)
        return 2
    if args.periodic is not None and args.periodic < 1:
        print("Error: --periodic must be at least 1 millisecond.", file=sys.stderr)
        return 2
    if args.periodic is None and not args.validate_only and not args.interface:
        print("Error: --interface is required unless --periodic is used.", file=sys.stderr)
        return 2

    try:
        controller = AdbEmulatorController(args.adb, args.serial)
        process_finder = WindowsQemuProcessFinder(args.qemu_pid)

        if args.validate_only:
            validate_environment(controller, process_finder)
            return 0

        dump_writer = WindowsMinidumpWriter()
        dump_coordinator = DumpCoordinator(
            controller=controller,
            process_finder=process_finder,
            dump_writer=dump_writer,
            dump_dir=args.dump_dir,
            hints_file=args.hints,
            staging_dir=args.staging_dir,
            skip_pause=args.skip_pause,
        )
        dump_coordinator.prepare_outputs()

        print(f"Target emulator: {controller.ensure_serial()} ({controller.avd_name()})")
        print(f"QEMU PID: {process_finder.find_pid()}")
        print(f"Dump Directory: {args.dump_dir}")
        print(f"Hints File: {args.hints}")
        if args.skip_pause:
            print("[!] --skip-pause enabled: dumping without pausing the AVD.")

        if args.periodic is not None:
            if args.ip:
                print("[!] --ip is ignored in periodic mode.")
            if args.interface:
                print("[!] --interface is ignored in periodic mode.")
            monitor = PeriodicDumpMonitor(
                interval_ms=args.periodic,
                dump_coordinator=dump_coordinator,
            )
            monitor.run()
        else:
            monitor = TrafficMonitor(
                target_ips=args.ip,
                interface=args.interface,
                app_data_packets=args.app_data_packets,
                dump_coordinator=dump_coordinator,
                layers=load_scapy(),
            )
            monitor.run()
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
