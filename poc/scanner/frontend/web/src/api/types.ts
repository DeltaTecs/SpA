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
  scheme: string | null;
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

export type PromptPartScope = "system" | "user";

export interface TaskPromptPart {
  id: string;
  title: string;
  scope: PromptPartScope;
  content: string;
  description: string;
}

export interface TaskTypeInfo {
  task_type: string;
  title: string;
  description: string;
  result_version: number;
  prompt_parts: TaskPromptPart[];
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
  prompt_overrides: Record<string, string>;
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

export type TaskStatusValue = "pending" | "running" | "done" | "error" | "cancelled";

export interface ExchangeTaskStatus {
  exchange_id: string;
  status: TaskStatusValue;
  result: TaskResult | null;
  error: string | null;
  iterations: number | null;
  stopped_on_limit: boolean | null;
  /** Human-readable current phase while running (null when not running). */
  activity: string | null;
}

export type JobStatusValue = "running" | "done" | "error" | "cancelled";

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

// --- pentest (scanner-backend, via /api/plan/pentest/*) --------------------

export type ToolCategory = "db" | "search" | "bash" | "hexstrike";

export interface McpToolInfo {
  name: string;
  description: string;
}

export interface McpToolsetInfo {
  name: string;
  category: ToolCategory;
  tools: McpToolInfo[];
}

export interface McpToolsResponse {
  toolsets: McpToolsetInfo[];
}

export type ReviewMode = "manual" | "automatic";
export type PentestVerdict = "confirmed" | "inconclusive" | "not_exploitable";

export interface ReviewerConfig {
  provider: string;
  model?: string | null;
  reasoning_effort?: ReasoningEffort | null;
  max_iterations: number;
}

export interface ToolConfig {
  exempt_db_search: boolean;
  allowed_tools: string[];
  tool_constraints: string;
  review_mode: ReviewMode;
  reviewer?: ReviewerConfig | null;
  review_auto_denied_manually: boolean;
}

export interface PentestItemInput {
  id: string;
  exchange: Exchange;
  check: VulnerabilityCheck;
}

export interface StartPentestJobRequest {
  recording_id: number;
  provider: string;
  model?: string | null;
  reasoning_effort?: ReasoningEffort | null;
  max_iterations: number;
  items: PentestItemInput[];
  concurrent: boolean;
  tool_config: ToolConfig;
  /** Persist the finished snapshot to db-api. The Analysis Queue sends false. */
  persist?: boolean;
}

export interface StartPentestJobResponse {
  job_id: string;
}

export interface PendingReview {
  review_id: string;
  item_id: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  auto_reason: string | null;
  created_at: number;
}

export interface PentestItemStatus {
  item_id: string;
  title: string;
  status: TaskStatusValue;
  result: TaskResult | null;
  error: string | null;
  iterations: number | null;
  stopped_on_limit: boolean | null;
  /** Human-readable current phase while running (null when not running). */
  activity: string | null;
  pending_reviews: PendingReview[];
}

export interface PentestJobStatus {
  job_id: string;
  status: JobStatusValue;
  provider: string;
  model: string | null;
  reasoning_effort: ReasoningEffort | null;
  items: PentestItemStatus[];
}

export interface ReviewDecisionRequest {
  approved: boolean;
  hint: string;
}

/** The `pentest` task payload shape. */
export interface PentestReportPayload {
  verdict: PentestVerdict;
  summary: string;
  evidence: string[];
  parse_warning?: string;
}

// --- exploit (scanner-backend, via /api/plan/exploit/*) --------------------

export type ExploitVerdict = "exploited" | "not_exploitable" | "inconclusive";

/** The carried-over analysis finding an exploit item starts from (from a
 *  completed Analysis Queue `pentest` report). */
export interface ExploitFinding {
  verdict: string;
  summary: string;
  evidence: string[];
}

export interface ExploitItemInput {
  id: string;
  exchange: Exchange;
  check: VulnerabilityCheck;
  finding: ExploitFinding;
}

export interface StartExploitJobRequest {
  recording_id: number;
  provider: string;
  model?: string | null;
  reasoning_effort?: ReasoningEffort | null;
  max_iterations: number;
  items: ExploitItemInput[];
  concurrent: boolean;
  tool_config: ToolConfig;
  /** Persist the finished snapshot to db-api. The Exploit Queue sends false. */
  persist?: boolean;
}

export interface StartExploitJobResponse {
  job_id: string;
}

/** The `exploit` task payload shape. */
export interface ExploitReportPayload {
  verdict: ExploitVerdict;
  applicability: string;
  exploitability: string;
  business_impact: string;
  proof_of_concept: string;
  evidence: string[];
  parse_warning?: string;
}

// --- guided analysis (scanner-backend, via /api/plan/guided/*) -------------

export type GuidedChatRole = "user" | "assistant";

/** One turn of the guided-analysis conversation (final content only). */
export interface GuidedChatMessage {
  role: GuidedChatRole;
  content: string;
}

export interface StartGuidedTurnRequest {
  provider: string;
  model?: string | null;
  reasoning_effort?: ReasoningEffort | null;
  max_iterations: number;
  /** System pretext; blank defers to the backend default. */
  system_prompt: string;
  /** Full prior conversation incl. the new user message (which must be last). */
  messages: GuidedChatMessage[];
  tool_config: ToolConfig;
}

export interface StartGuidedTurnResponse {
  job_id: string;
}

export interface GuidedTurnStatus {
  job_id: string;
  status: JobStatusValue;
  /** The assistant's final reply once the turn is done (null while running). */
  content: string | null;
  error: string | null;
  iterations: number | null;
  stopped_on_limit: boolean | null;
  /** Human-readable current phase while running (null when not running). */
  activity: string | null;
  pending_reviews: PendingReview[];
}

// --- persisted scan results (db-api /recordings/{id}/scans) ----------------

export interface ScanResultSummary {
  scan_result_id: number;
  recording_id: number;
  /** Producing task_type, e.g. "vulnerability_checks", or "pentest". */
  scan_type: string;
  /** Unix epoch milliseconds. */
  created_at: number;
  provider: string | null;
  model: string | null;
}

export interface ScanResultRecord extends ScanResultSummary {
  /** The stored job snapshot: a JobStatus or PentestJobStatus, by scan_type. */
  payload: Record<string, unknown>;
}

// --- tool-use transcript (Tool script page) --------------------------------

export type TranscriptStepKind = "reasoning" | "tool_call";
/** Tool categories plus "other" for an unrecognised toolset. */
export type TranscriptCategory = ToolCategory | "other";

/** One recorded step of an agentic run (mirrors the backend TranscriptStep). */
export interface TranscriptStep {
  kind: TranscriptStepKind;
  /** reasoning: the assistant's interim text emitted between tool calls. */
  text?: string | null;
  /** reasoning: the model's extended-thinking content, when the provider returns it. */
  reasoning?: string | null;
  // tool_call fields:
  call_id?: string | null;
  tool_name?: string | null;
  toolset_name?: string | null;
  category?: TranscriptCategory | null;
  arguments?: Record<string, unknown> | null;
  output?: string | null;
  /** Reviewer verdict: true/false, or null when no approver gated the call. */
  approved?: boolean | null;
  review_feedback?: string | null;
}

/** A recorded tool-use transcript for one analysis item or guided turn. */
export interface TranscriptDoc {
  item_id?: string | null;
  steps: TranscriptStep[];
}

// --- termination -----------------------------------------------------------

/** Per-server outcome of killing MCP tool processes during termination. */
export interface ToolTerminationInfo {
  name: string;
  category: ToolCategory;
  ok: boolean;
  detail: string;
}

/** Response to a job-cancel request. */
export interface TerminationResult {
  job_id: string;
  cancelled: boolean;
  tools: ToolTerminationInfo[];
}
