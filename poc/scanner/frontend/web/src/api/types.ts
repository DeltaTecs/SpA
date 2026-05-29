// TypeScript mirrors of the db-api Pydantic schemas (see poc/db/api/app).

export interface HttpSummary {
  method: string | null;
  host: string | null;
  path: string | null;
  status_code: number | null;
  status_text: string | null;
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

// --- LLM scan planning (scanner-backend, via /api/plan/*) ------------------

export interface Endpoint {
  ip: string | null;
  port: number | null;
}

export interface HttpExchangeInfo {
  method: string | null;
  path: string | null;
  endpoint_path: string | null;
  param_names: string[];
  status_code: number | null;
  host: string | null;
}

export type ExchangeKind = "conversation" | "http_pair";

export interface Exchange {
  id: string;
  kind: ExchangeKind;
  transport: string | null;
  local: Endpoint | null;
  remote: Endpoint | null;
  representative_packet_ids: number[];
  packet_count: number;
  payload_bytes: number;
  protocols: string[];
  http: HttpExchangeInfo | null;
  dedup_key: string | null;
}

export interface ExchangeList {
  recording_id: number;
  items: Exchange[];
}

export interface ProviderOption {
  type: string;
  requires_key: boolean;
  default_model: string | null;
  model_options: string[];
  reasoning_effort_options: ReasoningEffort[];
}

export interface ProviderList {
  providers: ProviderOption[];
}

export interface TaskTypeInfo {
  task_type: string;
  title: string;
  description: string;
  result_version: number;
}

export interface TaskTypeList {
  tasks: TaskTypeInfo[];
}

export interface StartJobRequest {
  recording_id: number;
  provider: string;
  model?: string | null;
  reasoning_effort?: ReasoningEffort | null;
  task_type: string;
  max_iterations: number;
  exchanges: Exchange[];
}

export interface StartJobResponse {
  job_id: string;
}

/** Generic, versioned envelope for any analysis task's structured output. */
export interface TaskResult {
  task_type: string;
  result_version: number;
  payload: Record<string, unknown>;
}

export type Severity = "info" | "low" | "medium" | "high" | "critical";

/** The `vulnerability_checks` task payload shape (`payload.checks`). */
export interface VulnerabilityCheck {
  title: string;
  description: string;
  rationale: string;
  severity: Severity;
  technique: string | null;
  references: string[];
}

export type TaskStatusValue = "pending" | "running" | "done" | "error";

export interface ExchangeTaskStatus {
  exchange_id: string;
  status: TaskStatusValue;
  result: TaskResult | null;
  error: string | null;
  iterations: number | null;
  stopped_on_limit: boolean | null;
}

export type JobStatusValue = "running" | "done" | "error";

export interface JobStatus {
  job_id: string;
  status: JobStatusValue;
  provider: string;
  model: string | null;
  reasoning_effort: ReasoningEffort | null;
  task_type: string;
  tasks: ExchangeTaskStatus[];
}

export type ReasoningEffort = "low" | "medium" | "high" | "max";
