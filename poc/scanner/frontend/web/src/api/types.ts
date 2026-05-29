// TypeScript mirrors of the db-api Pydantic schemas (see poc/db/api/app).

export interface HttpSummary {
  method: string | null;
  host: string | null;
  path: string | null;
  stream_id: number | null;
}

export interface PacketSummary {
  packet_id: number;
  recording_id: number | null;
  conversation_id: number | null;
  from_local: boolean | null;
  timestamp: number | null;
  number: number | null;
  protocols: string[];
  entropy: number | null;
  payload_length: number;
  remote_ip: string | null;
  remote_port: number | null;
  local_port: number | null;
  http: HttpSummary | null;
  association_key: string | null;
}

export interface PacketPage {
  items: PacketSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface IpHeader {
  src_addr: string | null;
  dst_addr: string | null;
}

export interface PortHeader {
  src_port: number | null;
  dst_port: number | null;
  length: number | null;
}

export interface HttpHeader {
  header_information_id: number;
  text_header: string | null;
  stream_id: number | null;
  version: number | null;
}

export interface PacketHeaders {
  ip: IpHeader | null;
  tcp: PortHeader | null;
  udp: PortHeader | null;
  http: HttpHeader[];
}

export interface PacketDetail extends PacketSummary {
  headers: PacketHeaders;
}

export interface PacketPayload {
  packet_id: number;
  encoding: string;
  clear_application_payload: string | null;
  clear_application_payload_length: number;
  packet_bytes: string | null;
  packet_bytes_length: number;
}

export interface RecordingInfo {
  recording_id: number;
  name: string | null;
  packet_count: number;
}

export interface NameCount {
  name: string;
  count: number;
}

export interface ProtocolSegment {
  name: string;
  protocols: NameCount[];
}

export interface DirectionCounts {
  incoming: number;
  outgoing: number;
  unknown: number;
}

export interface EntropyBucket {
  bucket: number;
  range_start: number;
  range_end: number;
  count: number;
}

export interface RemoteIp {
  ip: string;
  count: number;
}

export type EndpointNodeType = "ip" | "host" | "path";

export interface EndpointNode {
  name: string;
  type: EndpointNodeType;
  count: number;
  children: EndpointNode[];
}

export interface RecordingStats {
  recording_id: number;
  packet_count: number;
  protocol_distribution: NameCount[];
  protocol_segments: ProtocolSegment[];
  direction: DirectionCounts;
  entropy_histogram: EntropyBucket[];
  remote_ips: RemoteIp[];
  endpoint_tree: EndpointNode[];
}
