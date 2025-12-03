import os
import sys
import unittest
import shutil

# Add the project root to the path so we can import the module
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from util.ssl_decryptor import SSLKeylogDecryptor

PATH_TO_TSHARK = "D:\\prgm\\Wireshark\\tshark.exe"

class TestSSLDecryptor(unittest.TestCase):
    def setUp(self):
        self.resources_dir = os.path.join(os.path.dirname(__file__), 'resources')
        self.keylog_file = os.path.join(self.resources_dir, 'tls-keys.log')
        
        # Default to 'tshark' in PATH
        self.tshark_path = 'tshark'
        
        # If not in PATH, try common Windows paths
        if not shutil.which(self.tshark_path):
             possible_paths = [
                 PATH_TO_TSHARK,
                 "tshark"
             ]
             for p in possible_paths:
                 if os.path.exists(p):
                     self.tshark_path = p
                     break

    def test_decrypt_frame_15(self):
        pcap_file = os.path.join(self.resources_dir, 'discord_room_tcp_http.pcapng')

        decryptor = SSLKeylogDecryptor(self.tshark_path, self.keylog_file)
        
        if not decryptor.tshark_available:
            self.skipTest("tshark not found")

        decrypted_map = decryptor.decrypt_pcap(pcap_file)
        
        self.assertIn(15, decrypted_map, "Frame 15 should be decrypted")
        
        data = decrypted_map[15][0]
        full_content = (data.get('header') or b'') + (data.get('payload') or b'')
        expected_string = "uNDPo2O45eDk4VHILj34VeXoHm4="
        
        # Check if payload contains the expected bytes
        self.assertIn(expected_string.encode('utf-8'), full_content, f"Decrypted content of frame 15 should contain {expected_string}")

    def test_decrypt_frame_14_http2_header(self):
        pcap_file = os.path.join(self.resources_dir, 'discord_room_http2.pcapng')
        decryptor = SSLKeylogDecryptor(self.tshark_path, self.keylog_file)
        
        if not decryptor.tshark_available:
            self.skipTest("tshark not found")

        decrypted_map = decryptor.decrypt_pcap(pcap_file)
        
        self.assertIn(14, decrypted_map, "Frame 14 should be decrypted")
        
        expected_text = "PdWSFCtfKQ1atEViT0wWLkFibT"
        found = False
        
        for layer in decrypted_map[14]:
            content = b""
            if layer.get('header'):
                content += layer['header']
            if layer.get('payload'):
                content += layer['payload']
            
            if expected_text.encode('utf-8') in content:
                found = True
                break
        
        self.assertTrue(found, f"Frame 14 should contain header text: {expected_text}")

    def test_decrypt_frame_13(self):
        pcap_file = os.path.join(self.resources_dir, 'discord_room_tcp_http.pcapng')
        decryptor = SSLKeylogDecryptor(self.tshark_path, self.keylog_file)
        
        if not decryptor.tshark_available:
            self.skipTest("tshark not found")

        decrypted_map = decryptor.decrypt_pcap(pcap_file)
        
        self.assertIn(13, decrypted_map, "Frame 13 should be decrypted")
        
        data = decrypted_map[13][0]
        full_content = (data.get('header') or b'') + (data.get('payload') or b'')
        expected_string = "G6T9bvxVQzFD0+sCCMX26A=="
        
        # Check if payload contains the expected bytes
        self.assertIn(expected_string.encode('utf-8'), full_content, f"Decrypted content of frame 13 should contain {expected_string}")

    def test_decrypt_frame_9_no_payload(self):
        pcap_file = os.path.join(self.resources_dir, 'discord_room_tcp_http.pcapng')
        decryptor = SSLKeylogDecryptor(self.tshark_path, self.keylog_file)
        
        if not decryptor.tshark_available:
            self.skipTest("tshark not found")

        decrypted_map = decryptor.decrypt_pcap(pcap_file)
        
        # Frame 9 should either not be in the map, or have empty payload
        if 9 in decrypted_map:
            data = decrypted_map[9][0]
            payload = data.get('payload')
            self.assertTrue(payload is None or len(payload) == 0, "Frame 9 should not have a decrypted payload")

    def test_decrypt_quic_frame_23(self):
        quic_pcap_file = os.path.join(self.resources_dir, 'discord_room_quic.pcapng')
        decryptor = SSLKeylogDecryptor(self.tshark_path, self.keylog_file)
        
        if not decryptor.tshark_available:
            self.skipTest("tshark not found")

        decrypted_map = decryptor.decrypt_pcap(quic_pcap_file)
        
        self.assertIn(23, decrypted_map, "Frame 23 should be decrypted")
        
        data = decrypted_map[23][0]
        full_content = (data.get('header') or b'') + (data.get('payload') or b'')
        expected_string = "6be4534a6ab94f6ebe2482a0022d5663"
        
        # Check if payload contains the expected bytes
        self.assertIn(expected_string.encode('utf-8'), full_content, f"Decrypted content of frame 23 should contain {expected_string}")

    def test_decrypt_websocket_frame_7(self):
        pcap_file = os.path.join(self.resources_dir, 'discord_room_websocket_text.pcapng')
        decryptor = SSLKeylogDecryptor(self.tshark_path, self.keylog_file)
        
        if not decryptor.tshark_available:
            self.skipTest("tshark not found")

        decrypted_map = decryptor.decrypt_pcap(pcap_file)
        
        self.assertIn(7, decrypted_map, "Frame 7 should be decrypted")
        
        data = decrypted_map[7][0]
        full_content = (data.get('header') or b'') + (data.get('payload') or b'')
        expected_string = '{"timeout_ms":295235,"op":"hello","heartbeat_interval":41250}'
        
        # Check if payload contains the expected bytes
        self.assertIn(expected_string.encode('utf-8'), full_content, f"Decrypted content of frame 7 should contain {expected_string}")

    def test_decrypt_websocket_frame_17(self):
        pcap_file = os.path.join(self.resources_dir, 'discord_room_websocket_text.pcapng')
        decryptor = SSLKeylogDecryptor(self.tshark_path, self.keylog_file)
        
        if not decryptor.tshark_available:
            self.skipTest("tshark not found")

        decrypted_map = decryptor.decrypt_pcap(pcap_file)
        
        self.assertIn(17, decrypted_map, "Frame 17 should be decrypted")
        
        data = decrypted_map[17][0]
        full_content = (data.get('header') or b'') + (data.get('payload') or b'')
        expected_bytes = bytes.fromhex("03e8")
        
        # Check if payload is exactly the expected bytes
        self.assertEqual(full_content, expected_bytes, f"Decrypted content of frame 17 should be {expected_bytes.hex()}")

    def test_decrypt_websocket_bin_frame_120(self):
        pcap_file = os.path.join(self.resources_dir, 'discord_room_websocket_bin.pcapng')
        decryptor = SSLKeylogDecryptor(self.tshark_path, self.keylog_file)
        
        if not decryptor.tshark_available:
            self.skipTest("tshark not found")

        decrypted_map = decryptor.decrypt_pcap(pcap_file)
        
        self.assertIn(120, decrypted_map, "Frame 120 should be decrypted")
        
        data = decrypted_map[120][0]
        full_content = (data.get('header') or b'') + (data.get('payload') or b'')
        
        # Verify length
        self.assertEqual(len(full_content), 204660, "Payload length should be 204660 bytes")
        
        # Verify start bytes 0xdc1e01
        self.assertTrue(full_content.startswith(bytes.fromhex("dce101")), "Payload should start with 0xdc1e01")
        
        # Verify end bytes 0x3e14
        self.assertTrue(full_content.endswith(bytes.fromhex("3e14")), "Payload should end with 0x3e14")

    def test_decrypt_frame_15_header_protocol(self):
        pcap_file = os.path.join(self.resources_dir, 'discord_room_tcp_http.pcapng')
        decryptor = SSLKeylogDecryptor(self.tshark_path, self.keylog_file)
        
        if not decryptor.tshark_available:
            self.skipTest("tshark not found")

        decrypted_map = decryptor.decrypt_pcap(pcap_file)
        
        self.assertIn(15, decrypted_map, "Frame 15 should be decrypted")
        
        data = decrypted_map[15][0]
        header = data.get('header') or b''
        protocol = data.get('protocol')
        
        expected_string = "uNDPo2O45eDk4VHILj34VeXoHm4="
        
        # Check if header contains the expected bytes
        self.assertIn(expected_string.encode('utf-8'), header, f"Decrypted header of frame 15 should contain {expected_string}")
        
        # Check protocol
        self.assertEqual(protocol, "http", "Protocol should be http")

    def test_decrypt_wickr_dtls_frame_10(self):
        pcap_file = os.path.join(self.resources_dir, 'wickr_dtls.pcapng')
        
        decryptor = SSLKeylogDecryptor(self.tshark_path, self.keylog_file)
        
        if not decryptor.tshark_available:
            self.skipTest("tshark not found")

        decrypted_map = decryptor.decrypt_pcap(pcap_file)
        
        self.assertIn(10, decrypted_map, "Frame 10 should be decrypted")
        
        data = decrypted_map[10][0]
        full_content = (data.get('header') or b'') + (data.get('payload') or b'')
        expected_string = "bach.martin"
        
        # Check if payload contains the expected bytes
        self.assertIn(expected_string.encode('utf-8'), full_content, f"Decrypted content of frame 10 should contain {expected_string}")

    def test_decrypt_frame_43_http2_data(self):
        pcap_file = os.path.join(self.resources_dir, 'discord_room_http2.pcapng')
        decryptor = SSLKeylogDecryptor(self.tshark_path, self.keylog_file)
        
        if not decryptor.tshark_available:
            self.skipTest("tshark not found")

        decrypted_map = decryptor.decrypt_pcap(pcap_file)
        
        self.assertIn(43, decrypted_map, "Frame 43 should be decrypted")
        
        expected_bytes = bytes.fromhex("1f8b08000000000000ff554fcb6ec23010bcf7")
        found = False
        
        for layer in decrypted_map[43]:
            content = b""
            if layer.get('header'):
                content += layer['header']
            if layer.get('payload'):
                content += layer['payload']
            
            if expected_bytes in content:
                found = True
                break
        
        self.assertTrue(found, f"Frame 43 should contain data bytes: {expected_bytes.hex()}")

if __name__ == '__main__':
    unittest.main()
