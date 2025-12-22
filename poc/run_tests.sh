#!/bin/bash
echo "Running test_ssl_decryptor..."
docker exec pcap-processor python3 -m unittest util/test/test_ssl_decryptor.py

echo "Running test_parsing..."
docker exec -e DB_HOST=postgres pcap-processor python3 -m unittest parsing/test/test_parsing.py

echo "Running test_post_processing..."
docker exec -e DB_HOST=postgres pcap-processor python3 -m unittest parsing/test/test_post_processing.py
