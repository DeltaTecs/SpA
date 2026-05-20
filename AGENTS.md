# AI Agent Coding Hints

Produce code that is maintainable, and easy for humans to review. Keep security in mind. Write concise and helpful comments.

---

# `poc/` Project Architecture

A pipeline that turns raw network captures into LLM-driven vulnerability assessments. Stages are loosely coupled through a shared PostgreSQL database (`main`) and an MCP server that exposes the database to LLM agents.

## High-level pipeline

```
pcap file ─► [pcap_processing] ─► packets in DB ─► [grouping] ─► events in DB
                                                                  │
                                                                  ▼
                                                          [vuln_scan phase 1] ─► pre_scan in DB
                                                                  │
                                                                  ▼
                                                          [vuln_scan phase 2] ─► scans in DB
```

All services run via [poc/docker-compose.yml](poc/docker-compose.yml). The shared DB schema lives in [poc/db/init_db.sql](poc/db/init_db.sql).

## Where to find what

### Compose / configuration / DB
- [poc/docker-compose.yml](poc/docker-compose.yml) – wires all containers (`db`, `pgweb`, `pcap-processor`, `mcp-packet-db`, `mcp-hexstrike`, `grouping`, `scanner-llm`, `scanner-api`, `scanner-frontend`).
- [poc/db/init_db.sql](poc/db/init_db.sql) – schema: `recording`, `packet`, `conversation`, `protocol`, `*_header_information`, `event`, `packet_event`, `pre_scan`, `scan_type`, `scans`, `packet_processing_tag`, plus indexes and seeded `protocol` rows and `scan_type` rows.
- [poc/db/README.md](poc/db/README.md) – dump/load scripts.
- Runner wrappers at the repo top: [poc/run_parsing.sh](poc/run_parsing.sh), [poc/run_grouping.sh](poc/run_grouping.sh), [poc/reset_db.sh](poc/reset_db.sh), [poc/run_tests.sh](poc/run_tests.sh) (plus `.ps1` twins).

### 1. PCAP parsing — [poc/pcap_processing/](poc/pcap_processing/)
- [poc/pcap_processing/Dockerfile](poc/pcap_processing/Dockerfile) – Ubuntu + `tshark` + `scapy` + `psycopg2`.
- [poc/pcap_processing/run_pipeline_internal.sh](poc/pcap_processing/run_pipeline_internal.sh) – orchestrates pre-process → reset DB → pcap → DB → post-process.
- [poc/pcap_processing/parsing/pre_processing.py](poc/pcap_processing/parsing/pre_processing.py) – removes ARP, service discovery, empty TCP (currently bypassed in the runner).
- [poc/pcap_processing/parsing/pcap_to_db.py](poc/pcap_processing/parsing/pcap_to_db.py) – main importer: reads pcap, builds conversation IDs, inserts packet bytes + header info into Postgres.
- [poc/pcap_processing/parsing/packet_processor.py](poc/pcap_processing/parsing/packet_processor.py) – per-packet protocol detection, conversation grouping, payload extraction.
- [poc/pcap_processing/util/ssl_decryptor.py](poc/pcap_processing/util/ssl_decryptor.py) – TLS/QUIC decryption via SSLKEYLOGFILE through `tshark`.
- [poc/pcap_processing/parsing/post_processing/post_processing.py](poc/pcap_processing/parsing/post_processing/post_processing.py) – prunes bulky HTTP media payloads, decompresses gzip/brotli/zstd.
- [poc/pcap_processing/parsing/post_processing/discord_zstd_decompression.py](poc/pcap_processing/parsing/post_processing/discord_zstd_decompression.py) – Discord-specific zstd handling.
- [poc/pcap_processing/reset_db.py](poc/pcap_processing/reset_db.py) – drops/recreates the runtime role and re-applies `init_db.sql`.

### 2. Packet-DB MCP server — [poc/mcp/packet_db_server/](poc/mcp/packet_db_server/)
- [poc/mcp/packet_db_server/src/packet_db_server/server.py](poc/mcp/packet_db_server/src/packet_db_server/server.py) – FastMCP server exposing tools: `packet_info`, `packet_payload_hexdump`, `list_packet_ids`, `conversation_packets`, `packets_in_time_window`, `events`, `event_packets`, `events_for_recording`, `create_event`, `create_event_and_assign_packet`, `assign_packet_to_event`, `update_event_description`.
- [poc/mcp/packet_db_server/src/packet_db_server/database_access.py](poc/mcp/packet_db_server/src/packet_db_server/database_access.py) – `DatabaseAccess` wraps reads/writes and exposes structured packet metadata.
- [poc/mcp/packet_db_server/src/packet_db_server/packet_queries.py](poc/mcp/packet_db_server/src/packet_db_server/packet_queries.py) – SQL for packet text-rendering.
- [poc/mcp/packet_db_server/src/packet_db_server/event_queries.py](poc/mcp/packet_db_server/src/packet_db_server/event_queries.py) – SQL for events and tuple-filtered candidate matching.
- [poc/mcp/packet_db_server/src/packet_db_server/formatters.py](poc/mcp/packet_db_server/src/packet_db_server/formatters.py) – `hexdump` and similar text renderers.
- Listens on port 8765 in-network (streamable-http transport).

### 3. Grouping (packets → events) — [poc/grouping/](poc/grouping/)
- [poc/grouping/src/packet_analyzer.py](poc/grouping/src/packet_analyzer.py) – CLI entrypoint.
- [poc/grouping/src/analysis_runner.py](poc/grouping/src/analysis_runner.py) – main loop over packets in capture order.
- [poc/grouping/src/llm_analyzer.py](poc/grouping/src/llm_analyzer.py) – chat-model adapter (Ollama / OpenAI / Gemini / DeepSeek thinking mode); bounded tool-call loop.
- [poc/grouping/src/packet_tools.py](poc/grouping/src/packet_tools.py) – the LangChain tools the LLM is allowed to call (read-only context + `assign_current_packet_to_event` / `create_event_for_current_packet` / `update_event_description`).
- [poc/grouping/src/prompts.py](poc/grouping/src/prompts.py) – the grouping system prompt (definition of "event", tool rules).
- [poc/grouping/src/mcp_client.py](poc/grouping/src/mcp_client.py) – thin streamable-http client used by both grouping and vuln_scan.
- [poc/grouping/src/search_mcp_tools.py](poc/grouping/src/search_mcp_tools.py) – optional Tavily search MCP wiring.
- [poc/grouping/src/user_context.py](poc/grouping/src/user_context.py) – parses `app_details.txt` and the `MM:SS description` user-intend file.
- [poc/grouping/Dockerfile](poc/grouping/Dockerfile) – CUDA base + Python + Ollama (GPU-enabled).
- [poc/grouping/run_grouping_internal.sh](poc/grouping/run_grouping_internal.sh) – ensures Ollama is up, pulls the model, runs `packet_analyzer.py`.

### 4. Vulnerability scan — [poc/vuln_scan/](poc/vuln_scan/)
- HTTP API: [poc/vuln_scan/backend/api/app/main.py](poc/vuln_scan/backend/api/app/main.py) (FastAPI). Endpoints: `/config`, `/events`, `/prescans`, `/phase1`, `/phase2`, `/phase2/{run_id}`, `/phase2/{run_id}/abort`, `/phase2/{run_id}/tool/stop`, `/phase2/{run_id}/tool-requests/{request_id}/decision`, `/events/{event_id}/scans`.
- Storage helpers: [poc/vuln_scan/backend/api/app/prescan_store.py](poc/vuln_scan/backend/api/app/prescan_store.py) (phase-1 results), [poc/vuln_scan/backend/api/app/scan_store.py](poc/vuln_scan/backend/api/app/scan_store.py) (phase-2 results), [poc/vuln_scan/backend/api/app/analysis_sessions.py](poc/vuln_scan/backend/api/app/analysis_sessions.py) (in-memory phase-2 run state + tool-approval workflow).
- LLM/orchestration: [poc/vuln_scan/backend/llm/src/](poc/vuln_scan/backend/llm/src/)
  - [phase1_runner.py](poc/vuln_scan/backend/llm/src/phase1_runner.py), [phase2_runner.py](poc/vuln_scan/backend/llm/src/phase2_runner.py).
  - [event_context.py](poc/vuln_scan/backend/llm/src/event_context.py) – builds the prepared event context (packet facts + offsets) consumed by both phases.
  - [prompts.py](poc/vuln_scan/backend/llm/src/prompts.py) – phase-one and phase-two system prompts.
  - [analysis_types.py](poc/vuln_scan/backend/llm/src/analysis_types.py) – the analysis tracks ("Recon: Domain/Ports/HTTP", "Authentication", "Configuration", "Post Recon …") and the HexStrike MCP tool allow-list per track.
  - [packet_tools.py](poc/vuln_scan/backend/llm/src/packet_tools.py) – read-only LangChain wrappers around the packet-db MCP tools.
  - [mcp_proxy_tools.py](poc/vuln_scan/backend/llm/src/mcp_proxy_tools.py) – `PermissionedMCPToolProxy`: wraps remote MCP tools so every call goes through a human approve/deny callback (phase 2).
  - [llm_analyzer.py](poc/vuln_scan/backend/llm/src/llm_analyzer.py) – `ScannerAnalyzer` (multi-provider chat model + bounded tool loop).
  - [scanner_models.py](poc/vuln_scan/backend/llm/src/scanner_models.py) – `EventContext`, `PacketFact`, `ScanSummary` dataclasses.
  - [scanner_config.py](poc/vuln_scan/backend/llm/src/scanner_config.py) – provider/model resolution from env.
  - [user_context.py](poc/vuln_scan/backend/llm/src/user_context.py) – app-details / intend parsing (shared structure with grouping).
- Local LLM container: [poc/vuln_scan/backend/llm/Dockerfile](poc/vuln_scan/backend/llm/Dockerfile) – `scanner-llm` runs `ollama serve` on a GPU.
- Frontend: [poc/vuln_scan/frontend/](poc/vuln_scan/frontend/) – static SPA served by nginx, proxies `/api/*` to `scanner-api`. Main files: [index.html](poc/vuln_scan/frontend/index.html), [app.js](poc/vuln_scan/frontend/app.js), [styles.css](poc/vuln_scan/frontend/styles.css), [nginx.conf](poc/vuln_scan/frontend/nginx.conf).
- Default scan input files (overridable per request): [poc/vuln_scan/data/](poc/vuln_scan/data/).

### 5. Active scanning MCP — [poc/mcp/hexstrike/](poc/mcp/hexstrike/)
- [poc/mcp/hexstrike/Dockerfile](poc/mcp/hexstrike/Dockerfile) – assembles the HexStrike toolchain (subfinder, httpx, nuclei, nmap, gobuster, ffuf, sqlmap, etc.).
- [poc/mcp/hexstrike/entrypoint.sh](poc/mcp/hexstrike/entrypoint.sh) – picks one of `api / mcp / mcp-http / bash-mcp / shell`.
- [poc/mcp/hexstrike/bash_mcp_server.py](poc/mcp/hexstrike/bash_mcp_server.py) – the bash-execution MCP server (port 8766).
- [poc/mcp/hexstrike/http_mcp_bridge.py](poc/mcp/hexstrike/http_mcp_bridge.py) – streamable-http bridge in front of HexStrike's stdio MCP (port 8767).
- Wired into phase 2 via `PHASE2_MCP_SERVERS` env var in [poc/docker-compose.yml](poc/docker-compose.yml).

### 6. Search MCP — [poc/mcp/search_engine/](poc/mcp/search_engine/)
- Currently empty; if `TAVILY_API_KEY` or `SEARCH_MCP_URL` is configured, grouping and scanning attach Tavily's remote MCP (`https://mcp.tavily.com/mcp/`). Only `tavily_search` is exposed to the LLM.

---

# Stage Explanations

## Grouping stage — packets → events

**Goal.** Convert the flat per-packet table into a smaller set of purpose-scoped events. An "event" is defined (see [prompts.py](poc/grouping/src/prompts.py)) as *one packet or a small group of packets on one TCP/UDP connection that together perform the same application-level task* — login, telemetry upload, API request/response, key exchange, retry, keepalive, etc. A single connection can span many events; one event never spans connections.

**Driver.** [analysis_runner.run_analysis()](poc/grouping/src/analysis_runner.py) iterates the packets of one recording in capture order:

1. Skip packets that have neither a clear (decrypted) application payload nor an HTTP header (`DatabaseAccess.packet_analysis_metadata_for_recording`).
2. For each remaining packet, call the MCP `packet_info` tool to fetch a textual fact-sheet for the LLM.
3. Build a fresh tool set ([packet_tools.build_langchain_tools](poc/grouping/src/packet_tools.py)) scoped to the current packet:
   - Read-only context tools: `get_packet_info`, `get_full_payload`, `get_surrounding_packets`, `get_conversation_packets`, `get_packets_in_time_window`.
   - Tuple-filtered candidate lookup: `get_matching_events()` returns only events whose existing packets share the *normalized IP/port tuple* of the current packet — the server enforces this filter so the LLM cannot pick a mismatched event.
   - Mutating tools (exactly one is required per packet): `assign_current_packet_to_event(event_id, reason, confidence)` or `create_event_for_current_packet(description, reason, confidence)`; optional `update_event_description` afterwards.
4. Optionally attach a single external search tool (`search_engine__tavily_search`) for public reference material; everything else from Tavily is suppressed.
5. Optionally pass app-details (general description of the captured application) and time-aligned user actions (parsed from `MM:SS description` lines) so the LLM can map exchanges to user-visible behaviour.
6. Invoke the configured LLM ([llm_analyzer.PacketAnalyzer](poc/grouping/src/llm_analyzer.py)) with the system prompt from [prompts.py](poc/grouping/src/prompts.py) and a bounded number of tool-call rounds (default 6, with a forced "call an assignment tool now" reminder before the last round).
7. A `mutation_state` dict tracks whether an assignment tool was actually called; if not, the packet is counted as an error.

**Persistence.** Assignments go through the MCP server into `packet_event` (many-to-many) and `event` (`event.description`, optional `start_timestamp`/`end_timestamp`). The `reason` and `confidence` of the LLM are stored on the `packet_event` row.

**Result.** A clean, application-meaningful event timeline that the vulnerability scanner can iterate over instead of raw packets.

## Vulnerability scan – Phase 1 — security-relevant information from one event

**Goal.** Read-only triage. For one selected event, distil what happened and pick the single most promising entrypoint for active testing.

**Driver.** [phase1_runner.run_phase_one_summary()](poc/vuln_scan/backend/llm/src/phase1_runner.py), invoked from the API at `POST /phase1`:

1. [event_context.load_prepared_event_context()](poc/vuln_scan/backend/llm/src/event_context.py) fetches `event_packets`, parses the metadata header, and pulls `packet_info` for every assigned packet (up to `MAX_INITIAL_PACKET_INFOS=80`). It computes the event's recording-relative start/end offsets so user actions can be aligned.
2. Build read-only LangChain tools ([packet_tools.build_langchain_tools](poc/vuln_scan/backend/llm/src/packet_tools.py)): `packet_info`, `packet_payload_hexdump`, `conversation_packets`, `packets_in_time_window` — no mutating tools and no active scanner. The `packets_in_time_window` wrapper rejects recording IDs other than the event's own.
3. Optional search MCP tools are added if a search server is configured ([mcp_proxy_tools.build_auto_approved_mcp_tools](poc/vuln_scan/backend/llm/src/mcp_proxy_tools.py)); in phase 1 they are *auto-approved* — no human-in-the-loop.
4. [llm_analyzer.ScannerAnalyzer.summarize_event()](poc/vuln_scan/backend/llm/src/llm_analyzer.py) runs the chat-model loop with the phase-1 system prompt from [prompts.py](poc/vuln_scan/backend/llm/src/prompts.py). The prompt:
   - States this is read-only summarisation for an authorised bug-bounty / pentest.
   - Lists only the read-only tools.
   - Demands triage priorities (outbound requests, auth flows, state-changing actions over keepalives / ACKs / DNS).
   - Requires exactly one JSON object with `event_id`, `recording_id`, `most_interesting_packet_id`, `packet_content`, `event_summary`, `suspected_trigger`, `entrypoint_rationale`, `supporting_packet_ids`.
5. The JSON is parsed into [ScanSummary](poc/vuln_scan/backend/llm/src/scanner_models.py); `to_markdown()` produces the user-facing report.
6. The result is upserted into the `pre_scan` table keyed by `event_id` ([prescan_store.save_prescan](poc/vuln_scan/backend/api/app/prescan_store.py)) — one-to-one with the event. Re-running phase 1 replaces the stored row.

**Outcome.** A persisted, structured summary of one event plus the single best entrypoint packet — the prerequisite for phase 2 (the API rejects `/phase2` for any event without a `pre_scan`).

## Vulnerability scan – Phase 2 — live scanning of the remote service

**Goal.** Move from passive understanding to active probing of the remote endpoints referenced by the event, with a human-in-the-loop gate on every external tool call.

**Driver.** [phase2_runner.run_phase_two_analysis()](poc/vuln_scan/backend/llm/src/phase2_runner.py), invoked from the API at `POST /phase2` (which validates that a pre-scan exists and spawns a background thread, tracked by [AnalysisSessionStore](poc/vuln_scan/backend/api/app/analysis_sessions.py)).

1. Re-load the same prepared event context as phase 1 ([event_context.load_prepared_event_context](poc/vuln_scan/backend/llm/src/event_context.py)) and the persisted phase-1 markdown.
2. The user picks one or more analysis tracks from [analysis_types.py](poc/vuln_scan/backend/llm/src/analysis_types.py) (e.g. `Recon: Domain`, `Recon: Ports`, `Recon: HTTP Path/API`, `Authentication`, `Configuration`, `Post Recon - Explorative`, `Post Recon - High Impact`). Each track has a curated allow-list of HexStrike MCP tool names — `hexstrike_mcp_tools_for_analysis_types()` unions them.
3. Build a [PermissionedMCPToolProxy](poc/vuln_scan/backend/llm/src/mcp_proxy_tools.py) over the MCP servers configured in `PHASE2_MCP_SERVERS` (`packet=…:8765, hexstrike=…:8767, bash=…:8766`):
   - For each server it lists tools, filters HexStrike to the track allow-list, hides a few low-value packet tools (`event_packets`, `packet_info`, …) that would just re-emit context already in the prompt, and assigns a unique exposed name to each remaining tool.
   - Every call goes through `approval_callback` first. The API thread (`AnalysisRun.decide_tool_request`) parks the call as a `ToolApprovalRequest`, surfaces it to the frontend, and unblocks the run only after the operator approves or denies it. While a tool is running, the user can also request `tool/stop` — the proxy propagates that into the underlying MCP if it supports a control tool.
4. [ScannerAnalyzer.analyze_vulnerabilities()](poc/vuln_scan/backend/llm/src/llm_analyzer.py) runs the model with the phase-2 system prompt from [prompts.py](poc/vuln_scan/backend/llm/src/prompts.py). The prompt:
   - States this is an authorised pentest.
   - Restricts scope to targets and behaviour described in the event.
   - Lists the analysis tracks requested with their descriptions.
   - Tells the model that every tool call is proxied through a human.
   - Optionally folds in the phase-1 summary and prior phase-2 reports (`prior_report_ids`) to avoid repeated work.
5. The model interleaves reasoning, tool calls (recon → http enumeration → vuln scanners → bash on the HexStrike container), and progress messages until it emits a Markdown report. Progress is streamed back via `progress_callback`, and active tool executions are tracked so the UI can show the current command and allow stop.
6. The final Markdown is persisted with the run metadata (provider, model, constraints, tools used) into the `scans` table via [scan_store.save_completed_phase_two_scan()](poc/vuln_scan/backend/api/app/scan_store.py); the `scan_type` rows are seeded from `init_db.sql` and from [analysis_types.phase_two_scan_type_rows()](poc/vuln_scan/backend/llm/src/analysis_types.py).

**Outcome.** A reviewed, Markdown vulnerability report tied to the originating event, with a full audit trail of every approved/denied MCP tool call. Subsequent phase-2 runs on the same event can reference prior reports to extend rather than repeat the work.
