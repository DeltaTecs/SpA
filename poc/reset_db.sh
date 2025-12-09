#!/bin/bash
echo "Resetting database..."
docker exec pcap-processor python3 reset_db.py --host postgres
