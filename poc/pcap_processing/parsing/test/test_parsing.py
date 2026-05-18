import unittest
import subprocess
import psycopg2
import os
import sys
import argparse

# Add poc directory to sys.path to import reset_db
# This assumes the script is located at poc/parsing/test/test_parsing.py
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from reset_db import reset_db

class TestParsing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Get DB config from env vars (set in main)
        cls.db_host = os.environ.get('DB_HOST', 'localhost')
        cls.db_port = os.environ.get('DB_PORT', '5432')
        cls.db_name = os.environ.get('DB_NAME', 'main')
        cls.db_admin_user = os.environ.get('DB_ADMIN_USER', 'dbadmin')
        cls.db_admin_password = os.environ.get('DB_ADMIN_PASSWORD', 'dbadmin')
        cls.db_user = os.environ.get('DB_USER', 'dbuser')
        cls.db_password = os.environ.get('DB_PASSWORD', 'dbuser')
        
        # Paths
        cls.base_dir = os.path.dirname(os.path.abspath(__file__))
        cls.pcap_file = os.path.join(cls.base_dir, 'resources/discord_room.pcapng')
        cls.keylog_file = os.path.join(cls.base_dir, 'resources/tls-keys.log')
        cls.pcap_to_db_script = os.path.abspath(os.path.join(cls.base_dir, '../pcap_to_db.py'))
        cls.init_sql_path = os.path.abspath(os.path.join(cls.base_dir, '../../db/init_db.sql'))

        # Reset DB
        print(f"Resetting database {cls.db_name}...")
        reset_db(
            cls.db_host,
            cls.db_port,
            cls.db_name,
            cls.db_admin_user,
            cls.db_admin_password,
            cls.init_sql_path,
            cls.db_user,
            cls.db_password,
        )

        # Run pcap_to_db.py
        print("Running pcap_to_db.py...")
        cmd = [
            sys.executable, cls.pcap_to_db_script,
            '-i', cls.pcap_file,
            '-n', 'test_recording',
            '--db-host', cls.db_host,
            '--db-port', cls.db_port,
            '--db-name', cls.db_name,
            '--db-user', cls.db_user,
            '--db-password', cls.db_password,
            '--sslkeylog', cls.keylog_file
        ]
        
        # Run the script and capture output
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            raise RuntimeError(f"pcap_to_db.py failed with return code {result.returncode}")
        else:
            print("pcap_to_db.py finished successfully.")
            print("STDOUT:", result.stdout) # Uncomment for debugging

    def setUp(self):
        self.conn = psycopg2.connect(
            host=self.db_host,
            port=self.db_port,
            dbname=self.db_name,
            user=self.db_user,
            password=self.db_password
        )
        self.cur = self.conn.cursor()

    def tearDown(self):
        self.cur.close()
        self.conn.close()

    def test_frame_948_http3_stream(self):
        """
        Assert that frame 948 results in a packet entry in the database 
        and that this entry is linked to an http_header_information entry. 
        Assert that the http_header_information entry has stream_id set to 56.
        """
        # Assert that frame 948 results in a packet entry in the database
        self.cur.execute("SELECT packet_id FROM packet WHERE number = 948")
        row = self.cur.fetchone()
        self.assertIsNotNone(row, "Packet 948 not found in database")
        packet_id = row[0]

        # Assert that this entry is linked to an http_header_information entry
        # and that the http_header_information entry has stream_id set to 56
        query = """
            SELECT h.stream_id
            FROM packet_header_information phi
            JOIN http_header_information h ON phi.header_information_id = h.header_information_id
            WHERE phi.packet_id = %s
        """
        self.cur.execute(query, (packet_id,))
        rows = self.cur.fetchall()
        
        self.assertTrue(len(rows) > 0, "No http_header_information linked to packet 948")
        
        # Check if any of the linked http headers has stream_id 56
        stream_ids = [r[0] for r in rows]
        self.assertIn(56, stream_ids, f"Stream ID 56 not found in http headers for packet 948. Found: {stream_ids}")

    def test_frame_25_http_control_stream(self):
        """
        Assert that packet number 25 is linked to an http_header_information entry 
        that has null text_header. This packet is part of an http control stream.
        """
        # Assert that frame 25 results in a packet entry in the database
        self.cur.execute("SELECT packet_id FROM packet WHERE number = 25")
        row = self.cur.fetchone()
        self.assertIsNotNone(row, "Packet 25 not found in database")
        packet_id = row[0]

        # Assert that this entry is linked to an http_header_information entry
        # and that the http_header_information entry has text_header set to NULL
        query = """
            SELECT h.text_header
            FROM packet_header_information phi
            JOIN http_header_information h ON phi.header_information_id = h.header_information_id
            WHERE phi.packet_id = %s
        """
        self.cur.execute(query, (packet_id,))
        rows = self.cur.fetchall()
        
        self.assertTrue(len(rows) > 0, "No http_header_information linked to packet 25")
        
        # Check if any of the linked http headers has text_header as None
        text_headers = [r[0] for r in rows]
        self.assertIn(None, text_headers, f"NULL text_header not found in http headers for packet 25. Found: {text_headers}")

    def test_only_http1_packets_have_null_stream_id(self):
        """
        Assert that only HTTP 1 packets have stream_id NULL in the http_header_information table.
        """
        self.cur.execute("SELECT text_header, stream_id FROM http_header_information")
        rows = self.cur.fetchall()
        
        for text_header, stream_id in rows:
            if stream_id is None:
                # If stream_id is NULL, it MUST be HTTP/1
                is_http1 = False
                if text_header:
                    first_line = text_header.split('\r\n')[0]
                    if "HTTP/1" in first_line:
                        is_http1 = True
                
                self.assertTrue(is_http1, f"Packet with NULL stream_id is not HTTP/1. Header: {text_header}")

    def test_frame_541_linked_to_header_of_425(self):
        """
        Assert that frame 541 is linked to the same http_header_information as frame 425.
        Frames 444, 442 and 425 are linked to. 425 carried the http text header that is relevant to 541, 442 and 444.
        """
        # Get packet IDs for the frames
        frames = [541, 444, 442, 425]
        packet_ids = {}
        
        for frame_num in frames:
            self.cur.execute("SELECT packet_id FROM packet WHERE number = %s", (frame_num,))
            row = self.cur.fetchone()
            self.assertIsNotNone(row, f"Packet {frame_num} not found in database")
            packet_ids[frame_num] = row[0]

        # Get header_information_id for each packet
        header_info_ids = {}
        query = """
            SELECT h.header_information_id
            FROM packet_header_information phi
            JOIN http_header_information h ON phi.header_information_id = h.header_information_id
            WHERE phi.packet_id = %s
        """
        
        for frame_num, pkt_id in packet_ids.items():
            self.cur.execute(query, (pkt_id,))
            rows = self.cur.fetchall()
            header_info_ids[frame_num] = set(r[0] for r in rows)

        # Check that 425 has at least one header
        self.assertTrue(len(header_info_ids[425]) > 0, "Frame 425 should have http header info")
        
        # The header info from 425 should be present in 541, 444, 442
        common_headers_541 = header_info_ids[425].intersection(header_info_ids[541])
        self.assertTrue(len(common_headers_541) > 0, f"Frame 541 does not share an http header with frame 425. 425: {header_info_ids[425]}, 541: {header_info_ids[541]}")
        
        common_headers_444 = header_info_ids[425].intersection(header_info_ids[444])
        self.assertTrue(len(common_headers_444) > 0, f"Frame 444 does not share an http header with frame 425. 425: {header_info_ids[425]}, 444: {header_info_ids[444]}")

        common_headers_442 = header_info_ids[425].intersection(header_info_ids[442])
        self.assertTrue(len(common_headers_442) > 0, f"Frame 442 does not share an http header with frame 425. 425: {header_info_ids[425]}, 442: {header_info_ids[442]}")

    def test_frame_5855_linked_to_same_http_header_as_5854(self):
        """
        Verify that frame nr 5855 in packet is linked to the same http_header_information as frame 5854.
        The http header text in the database should contain the string "59d982c7f10db42dd49c85f9b2879b2ba358c8fecc593c3e63"
        """
        # Get packet_ids for frames 5854 and 5855
        self.cur.execute("SELECT packet_id, number FROM packet WHERE number IN (5854, 5855)")
        rows = self.cur.fetchall()
        packet_map = {row[1]: row[0] for row in rows}
        
        self.assertIn(5854, packet_map, "Packet 5854 not found in database")
        self.assertIn(5855, packet_map, "Packet 5855 not found in database")
        
        packet_id_5854 = packet_map[5854]
        packet_id_5855 = packet_map[5855]

        # Get header_information_ids and text for these packets
        # We specifically look for http_header_information
        query = """
            SELECT phi.packet_id, h.header_information_id, h.text_header
            FROM packet_header_information phi
            JOIN http_header_information h ON phi.header_information_id = h.header_information_id
            WHERE phi.packet_id IN (%s, %s)
        """
        self.cur.execute(query, (packet_id_5854, packet_id_5855))
        results = self.cur.fetchall()
        
        # Map packet_id to list of (header_id, text)
        packet_headers = {}
        for pid, hid, text in results:
            if pid not in packet_headers:
                packet_headers[pid] = []
            packet_headers[pid].append((hid, text))

        self.assertIn(packet_id_5854, packet_headers, "Packet 5854 has no http header info")
        self.assertIn(packet_id_5855, packet_headers, "Packet 5855 has no http header info")

        # Find the common header_information_id
        headers_5854 = packet_headers[packet_id_5854]
        headers_5855 = packet_headers[packet_id_5855]
        
        common_header = None
        target_string = "59d982c7f10db42dd49c85f9b2879b2ba358c8fecc593c3e63"
        
        # Check if there is a common header and if it contains the string
        found_common = False
        for h54 in headers_5854:
            for h55 in headers_5855:
                if h54[0] == h55[0]: # Same header_information_id
                    found_common = True
                    # Check text
                    if h54[1] and target_string in h54[1]:
                        common_header = h54
                        break
            if common_header:
                break
        
        self.assertTrue(found_common, "Frames 5854 and 5855 are not linked to the same http_header_information")
        self.assertIsNotNone(common_header, f"The common http header does not contain the string '{target_string}'")

    def test_frame_1496_http_header(self):
        """
        Assert that frame 1496 results in a packet entry in the database
        and that this entry is linked to an http_header_information entry.
        Assert that the http_header_information entry has version set to 1
        and text_header contains "oBR4Ft4AILRqKPcm0FtVW1d0JRv58Bf7jj32Y".
        """
        # Assert that frame 1496 results in a packet entry in the database
        self.cur.execute("SELECT packet_id FROM packet WHERE number = 1496")
        row = self.cur.fetchone()
        self.assertIsNotNone(row, "Packet 1496 not found in database")
        packet_id = row[0]

        # Assert that this entry is linked to an http_header_information entry
        # and that the http_header_information entry has version set to 1
        # and text_header contains the specified string
        query = """
            SELECT h.version, h.text_header
            FROM packet_header_information phi
            JOIN http_header_information h ON phi.header_information_id = h.header_information_id
            WHERE phi.packet_id = %s
        """
        self.cur.execute(query, (packet_id,))
        rows = self.cur.fetchall()
        
        self.assertTrue(len(rows) > 0, "No http_header_information linked to packet 1496")
        
        found = False
        for r in rows:
            version = r[0]
            text_header = r[1]
            if version == 1 and text_header and "oBR4Ft4AILRqKPcm0FtVW1d0JRv58Bf7jj32Y" in text_header:
                found = True
                break
        
        self.assertTrue(found, "HTTP header with version 1 and specified text not found for packet 1496")

if __name__ == '__main__':
    # Parse arguments to allow configuring the test database
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--db-host", default="localhost", help="Database host")
    parser.add_argument("--db-port", default="5432", help="Database port")
    parser.add_argument("--db-name", default="main", help="Database name")
    parser.add_argument("--db-admin-user", default="dbadmin", help="Database admin user")
    parser.add_argument("--db-admin-password", default="dbadmin", help="Database admin password")
    parser.add_argument("--db-user", default="dbuser", help="Database user")
    parser.add_argument("--db-password", default="dbuser", help="Database password")
    
    args, remaining_argv = parser.parse_known_args()
    
    # Pass config to TestParsing via env vars
    os.environ['DB_HOST'] = args.db_host
    os.environ['DB_PORT'] = str(args.db_port)
    os.environ['DB_NAME'] = args.db_name
    os.environ['DB_ADMIN_USER'] = args.db_admin_user
    os.environ['DB_ADMIN_PASSWORD'] = args.db_admin_password
    os.environ['DB_USER'] = args.db_user
    os.environ['DB_PASSWORD'] = args.db_password
    
    # Update sys.argv so unittest doesn't get confused by our args
    sys.argv = [sys.argv[0]] + remaining_argv
    
    unittest.main()
