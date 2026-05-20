import unittest
import subprocess
import psycopg2
import os
import sys

# Add poc directory to sys.path to import reset_db
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))
from reset_db import reset_db

class TestPostProcessing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Get DB config from env vars (set in main)test_packet_851
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
        cls.post_processing_script = os.path.abspath(os.path.join(cls.base_dir, '../post_processing/post_processing.py'))
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
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode != 0:
            print("STDOUT:", result.stdout)
            print("STDERR:", result.stderr)
            raise RuntimeError(f"pcap_to_db.py failed with return code {result.returncode}")
        else:
            print("pcap_to_db.py finished successfully.")

        # Get recording ID
        conn = psycopg2.connect(
            host=cls.db_host,
            port=cls.db_port,
            dbname=cls.db_name,
            user=cls.db_user,
            password=cls.db_password
        )
        cur = conn.cursor()
        cur.execute("SELECT recording_id FROM recording WHERE name = 'test_recording'")
        cls.recording_id = cur.fetchone()[0]
        cur.close()
        conn.close()

        # Run post_processing.py
        print("Running post_processing.py...")
        cmd_pp = [
            sys.executable, cls.post_processing_script,
            '--recording-id', str(cls.recording_id),
            '--db-host', cls.db_host,
            '--db-port', cls.db_port,
            '--db-name', cls.db_name,
            '--db-user', cls.db_user,
            '--db-password', cls.db_password
        ]
        
        result_pp = subprocess.run(cmd_pp, capture_output=True, text=True)
        if result_pp.returncode != 0:
            print("STDOUT:", result_pp.stdout)
            print("STDERR:", result_pp.stderr)
            raise RuntimeError(f"post_processing.py failed with return code {result_pp.returncode}")
        else:
            print("post_processing.py finished successfully.")

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

    def test_packet_366_decompression(self):
        """
        Check that the frame with packet number 366 results in a clear_application_payload 
        after post processing that contains the string "s0AVycw/OT48O8FgwETti6IcdqQV1s"
        """
        self.cur.execute("SELECT clear_application_payload FROM packet WHERE number = 366 AND recording_id = %s", (self.recording_id,))
        row = self.cur.fetchone()
        self.assertIsNotNone(row, "Packet 366 not found in database")
        
        payload = row[0]
        self.assertIsNotNone(payload, "Packet 366 has no clear_application_payload")
        
        # payload is bytes (bytea in db), so we need to decode or check bytes
        # The user said "contains the string ...". 
        # If the payload is text, it might be bytes in python.
        
        target_string = "s0AVycw/OT48O8FgwETti6IcdqQV1s"
        
        # Try to decode as utf-8 to check string, or check as bytes
        try:
            payload_str = bytes(payload).decode('utf-8', errors='ignore')
            self.assertIn(target_string, payload_str, f"Target string '{target_string}' not found in payload of packet 366")
        except Exception as e:
            self.fail(f"Failed to decode payload: {e}")

    def test_packet_5855_content(self):
        """
        Check that the frame with packet number 5855 results in a clear_application_payload 
        after post processing that contains the string "oimompecagnajdejgnnjijobebaeigek"
        """
        self.cur.execute("SELECT clear_application_payload FROM packet WHERE number = 5855 AND recording_id = %s", (self.recording_id,))
        row = self.cur.fetchone()
        self.assertIsNotNone(row, "Packet 5855 not found in database")
        
        payload = row[0]
        self.assertIsNotNone(payload, "Packet 5855 has no clear_application_payload")
        
        target_string = "oimompecagnajdejgnnjijobebaeigek"
        
        try:
            payload_str = bytes(payload).decode('utf-8', errors='ignore')
            self.assertIn(target_string, payload_str, f"Target string '{target_string}' not found in payload of packet 5855")
        except Exception as e:
            self.fail(f"Failed to decode payload: {e}")

    def test_packet_851_content(self):
        """
        Check that the frame with packet number 851 results in a clear_application_payload 
        after post processing that contains the string "rd dein aktuelles Abonnement ersetzt."
        """
        self.cur.execute("SELECT clear_application_payload FROM packet WHERE number = 851 AND recording_id = %s", (self.recording_id,))
        row = self.cur.fetchone()
        self.assertIsNotNone(row, "Packet 851 not found in database")
        
        payload = row[0]
        self.assertIsNotNone(payload, "Packet 851 has no clear_application_payload")
        
        target_string = "rd dein aktuelles Abonnement ersetzt."
        
        try:
            payload_str = bytes(payload).decode('utf-8', errors='ignore')
            self.assertIn(target_string, payload_str, f"Target string '{target_string}' not found in payload of packet 851")
        except Exception as e:
            self.fail(f"Failed to decode payload: {e}")

    def test_packet_1566_content(self):
        """
        Check that the frame with packet number 1566 results in a clear_application_payload 
        that equals the bytes 0x5b5d0a
        """
        self.cur.execute("SELECT clear_application_payload FROM packet WHERE number = 1566 AND recording_id = %s", (self.recording_id,))
        row = self.cur.fetchone()
        self.assertIsNotNone(row, "Packet 1566 not found in database")
        
        payload = row[0]
        self.assertIsNotNone(payload, "Packet 1566 has no clear_application_payload")
        
        target_bytes = bytes.fromhex('5b5d0a')
        
        self.assertEqual(bytes(payload), target_bytes, f"Payload of packet 1566 does not match expected bytes {target_bytes.hex()}")

    def test_packet_624_content(self):
        """
        Check that the frame with packet number 624 results in a clear_application_payload 
        after post processing that contains the string "gateway-prd-arm-us-east1-d-bzvc"
        """
        self.cur.execute("SELECT clear_application_payload FROM packet WHERE number = 624 AND recording_id = %s", (self.recording_id,))
        row = self.cur.fetchone()
        self.assertIsNotNone(row, "Packet 624 not found in database")
        
        payload = row[0]
        self.assertIsNotNone(payload, "Packet 624 has no clear_application_payload")
        
        target_string = "gateway-prd-arm-us-east1-d-bzvc"
        
        try:
            payload_str = bytes(payload).decode('utf-8', errors='ignore')
            self.assertIn(target_string, payload_str, f"Target string '{target_string}' not found in payload of packet 624")
        except Exception as e:
            self.fail(f"Failed to decode payload: {e}")

if __name__ == '__main__':
    unittest.main()
