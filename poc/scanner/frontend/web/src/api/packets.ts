import { apiGet, buildQuery } from "./client";
import type { PacketDetail, PacketPage, PacketPayload } from "./types";

export type AppProtocolFilter = "http" | "websocket" | "other";

export interface PacketQuery {
  recording_id?: number;
  conversation_id?: number;
  protocol?: string;
  from_local?: boolean;
  has_clear_payload?: boolean;
  has_http_header_text?: boolean;
  app_protocol?: AppProtocolFilter;
  limit?: number;
  offset?: number;
}

export function listPackets(query: PacketQuery): Promise<PacketPage> {
  return apiGet<PacketPage>(`/packets${buildQuery(query)}`);
}

export function getPacket(packetId: number): Promise<PacketDetail> {
  return apiGet<PacketDetail>(`/packets/${packetId}`);
}

export function getPayload(packetId: number): Promise<PacketPayload> {
  return apiGet<PacketPayload>(`/packets/${packetId}/payload`);
}
