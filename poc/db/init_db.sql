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

-- Event table
CREATE TABLE IF NOT EXISTS event (
  event_id bigserial PRIMARY KEY,
  description text,
  start_timestamp bigint DEFAULT NULL,
  end_timestamp bigint DEFAULT NULL
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

-- Many-to-many between packet and event
CREATE TABLE IF NOT EXISTS packet_event (
  packet_id bigint NOT NULL REFERENCES packet(packet_id) ON DELETE CASCADE,
  event_id bigint NOT NULL REFERENCES event(event_id) ON DELETE CASCADE,
  reason text,
  confidence double precision,
  PRIMARY KEY (packet_id, event_id)
);

ALTER TABLE packet_event ADD COLUMN IF NOT EXISTS reason text;
ALTER TABLE packet_event ADD COLUMN IF NOT EXISTS confidence double precision;

-- One persisted phase-one pre-scan per event.
CREATE TABLE IF NOT EXISTS pre_scan (
  event_id bigint PRIMARY KEY REFERENCES event(event_id) ON DELETE CASCADE,
  recording_id bigint REFERENCES recording(recording_id) ON DELETE SET NULL,
  most_interesting_packet_id bigint REFERENCES packet(packet_id) ON DELETE SET NULL,
  packet_content text NOT NULL DEFAULT '',
  event_summary text NOT NULL DEFAULT '',
  suspected_trigger text NOT NULL DEFAULT '',
  entrypoint_rationale text NOT NULL DEFAULT '',
  supporting_packet_ids bigint[] NOT NULL DEFAULT ARRAY[]::bigint[]
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

-- Indexes for event + packet_event lookups
CREATE INDEX IF NOT EXISTS idx_event_time_range ON event(start_timestamp, end_timestamp);
CREATE INDEX IF NOT EXISTS idx_packet_event_event_id ON packet_event(event_id);
