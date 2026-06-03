-- init_db.sql
-- Creates schema for `main` database and seeds default protocol names and stacks
-- Uses PostgreSQL table inheritance for header-specific tables

BEGIN;

-- Protocols
CREATE TABLE IF NOT EXISTS protocol (
  protocol_id bigserial PRIMARY KEY,
  name text NOT NULL UNIQUE
);

-- Note: `protocol_stack` table removed.
-- Packets will store an ordered list of protocol_name IDs in the `protocol_name_ids` bigint[] column.

-- Recording table
CREATE TABLE IF NOT EXISTS recording (
  recording_id bigserial PRIMARY KEY,
  name text,
  timestamp bigint
);

-- Conversation table
CREATE TABLE IF NOT EXISTS conversation (
  conversation_id bigserial PRIMARY KEY
);

-- Header information (parent)
CREATE TABLE IF NOT EXISTS header_information (
  header_information_id bigserial PRIMARY KEY,
  protocol_id bigint REFERENCES protocol(protocol_id)
);

-- UDP header info inherits header_information
CREATE TABLE IF NOT EXISTS udp_header_information (
  src_port integer,
  dst_port integer,
  length integer
) INHERITS (header_information);

-- TCP header info inherits header_information
CREATE TABLE IF NOT EXISTS tcp_header_information (
  src_port integer,
  dst_port integer,
  length integer
) INHERITS (header_information);

-- HTTP header info inherits header_information
CREATE TABLE IF NOT EXISTS http_header_information (
  text_header text,
  stream_id bigint,
  version integer
) INHERITS (header_information);

-- IP header info inherits header_information
CREATE TABLE IF NOT EXISTS ip_header_information (
  src_addr text,
  dst_addr text
) INHERITS (header_information);
-- Packet table (stores ordered list of protocol_name IDs)
CREATE TABLE IF NOT EXISTS packet (
  packet_id bigserial PRIMARY KEY,
  recording_id bigint REFERENCES recording(recording_id) ON DELETE CASCADE,
  conversation_id bigint REFERENCES conversation(conversation_id) ON DELETE SET NULL,
  from_local boolean,
  timestamp bigint,
  number bigint,
  protocol_ids bigint[] NOT NULL,
  packet_bytes bytea,
  clear_application_payload bytea,
  entropy float
);

-- Many-to-many between packet and header_information
CREATE TABLE IF NOT EXISTS packet_header_information (
  packet_id bigint NOT NULL REFERENCES packet(packet_id) ON DELETE CASCADE,
  header_information_id bigint NOT NULL REFERENCES header_information(header_information_id) ON DELETE CASCADE,
  PRIMARY KEY (packet_id, header_information_id)
);

-- Processing tag table
CREATE TABLE IF NOT EXISTS packet_processing_tag (
  packet_processing_tag_id bigserial PRIMARY KEY,
  packet_id bigint REFERENCES packet(packet_id) ON DELETE CASCADE,
  step text
);

-- Recording processing tag table
CREATE TABLE IF NOT EXISTS recording_processing_tag (
  recording_processing_tag_id bigserial PRIMARY KEY,
  recording_id bigint REFERENCES recording(recording_id) ON DELETE CASCADE,
  step text
);

-- Persisted scan results: a finished scan's full snapshot (the same JobStatus /
-- PentestJobStatus the scanner-backend serves) stored as JSON so the UI can
-- reload the last vulnerability-check suggestions and pentest reports per
-- recording. `scan_type` is the producing analysis task_type (e.g.
-- 'vulnerability_checks') or 'pentest'; left unconstrained so new pluggable
-- task types persist without a schema change.
CREATE TABLE IF NOT EXISTS scan_result (
  scan_result_id bigserial PRIMARY KEY,
  recording_id bigint NOT NULL REFERENCES recording(recording_id) ON DELETE CASCADE,
  scan_type text NOT NULL,
  created_at bigint NOT NULL,  -- unix epoch milliseconds
  provider text,
  model text,
  payload jsonb NOT NULL
);

-- Tool-use transcript for one analysed item of a scan_result: the ordered MCP
-- tool calls (arguments + output), the model's reasoning between them, and the
-- reviewer's approve/deny decisions. Kept in a side table (not in scan_result's
-- payload) so it is fetched only on demand and pruned with its parent via CASCADE.
-- Provides the strict, auditable documentation of every step taken to a finding.
CREATE TABLE IF NOT EXISTS scan_transcript (
  scan_transcript_id bigserial PRIMARY KEY,
  scan_result_id bigint NOT NULL REFERENCES scan_result(scan_result_id) ON DELETE CASCADE,
  item_id text NOT NULL,
  steps jsonb NOT NULL
);

-- Seed default protocol names
INSERT INTO protocol (name) VALUES
  ('IP'),('IPv6'),('UDP'), ('TCP'), ('DNS'), ('TLS'), ('QUIC'), ('DTLS'), ('STUN'), ('TURN'),('RTP'),('RTCP'), ('HTTP'), ('Websocket')
ON CONFLICT (name) DO NOTHING;

-- protocol_stack concept removed; packet now references ordered protocol_name_ids

COMMIT;

-- Create some helpful indexes
CREATE INDEX IF NOT EXISTS idx_packet_recording ON packet(recording_id);
-- GIN index for array lookups on `protocol_ids`
CREATE INDEX IF NOT EXISTS idx_packet_protocol_ids ON packet USING GIN (protocol_ids);
-- Index for conversation lookup
CREATE INDEX IF NOT EXISTS idx_packet_conversation ON packet(conversation_id);
-- Indexes for per-packet header enrichment lookups
CREATE INDEX IF NOT EXISTS idx_ip_header_information_header_id
  ON ip_header_information(header_information_id);
CREATE INDEX IF NOT EXISTS idx_tcp_header_information_header_id
  ON tcp_header_information(header_information_id);
CREATE INDEX IF NOT EXISTS idx_udp_header_information_header_id
  ON udp_header_information(header_information_id);
CREATE INDEX IF NOT EXISTS idx_http_header_information_header_id
  ON http_header_information(header_information_id);
-- Newest-first lookup of stored scans per recording and type
CREATE INDEX IF NOT EXISTS idx_scan_result_recording_type
  ON scan_result(recording_id, scan_type, created_at DESC, scan_result_id DESC);
-- One transcript per (scan_result, item); also the lookup path for the Tool-script page
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_transcript_result_item
  ON scan_transcript(scan_result_id, item_id);
