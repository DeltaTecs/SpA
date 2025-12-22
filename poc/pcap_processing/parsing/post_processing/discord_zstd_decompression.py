import logging
import zstandard as zstd
from etf_decode import etf_decode

def decompress_discord_zstd(conn, recording_id: int):
    """
    Looks for http headers with 'compress=zstd-stream', finds associated Websocket packets,
    and attempts to decompress them using a zstd streaming decompressor.
    """
    cur = conn.cursor()
    try:
        # 1. Find trigger packets and their ports
        # We look for headers containing 'compress=zstd-stream'
        cur.execute("""
            SELECT DISTINCT
                tcp.src_port, tcp.dst_port,
                udp.src_port, udp.dst_port
            FROM http_header_information h
            JOIN packet_header_information phi ON h.header_information_id = phi.header_information_id
            JOIN packet p ON phi.packet_id = p.packet_id
            LEFT JOIN packet_header_information phi_tcp ON p.packet_id = phi_tcp.packet_id
            LEFT JOIN tcp_header_information tcp ON phi_tcp.header_information_id = tcp.header_information_id
            LEFT JOIN packet_header_information phi_udp ON p.packet_id = phi_udp.packet_id
            LEFT JOIN udp_header_information udp ON phi_udp.header_information_id = udp.header_information_id
            WHERE p.recording_id = %s
              AND h.text_header LIKE '%%compress=zstd-stream%%'
        """, (recording_id,))
        
        relevant_connections = set()
        for row in cur.fetchall():
            # row is (tcp_src, tcp_dst, udp_src, udp_dst)
            t_src, t_dst, u_src, u_dst = row
            if t_src is not None and t_dst is not None:
                relevant_connections.add(tuple(sorted((t_src, t_dst))))
            if u_src is not None and u_dst is not None:
                relevant_connections.add(tuple(sorted((u_src, u_dst))))
        
        if not relevant_connections:
            return

        # 2. Retrieve Websocket packets matching these ports
        cur.execute("SELECT protocol_id FROM protocol WHERE name = 'Websocket'")
        ws_proto_id_row = cur.fetchone()
        if not ws_proto_id_row:
            return
        ws_proto_id = ws_proto_id_row[0]

        # Get packets that have Websocket protocol and are in the recording
        cur.execute("""
            SELECT p.packet_id, p.number, p.clear_application_payload, p.entropy,
                   MAX(tcp.src_port), MAX(tcp.dst_port), MAX(udp.src_port), MAX(udp.dst_port)
            FROM packet p
            LEFT JOIN packet_header_information phi ON p.packet_id = phi.packet_id
            LEFT JOIN tcp_header_information tcp ON phi.header_information_id = tcp.header_information_id
            LEFT JOIN udp_header_information udp ON phi.header_information_id = udp.header_information_id
            WHERE p.recording_id = %s
              AND %s = ANY(p.protocol_ids)
              AND p.clear_application_payload IS NOT NULL
            GROUP BY p.packet_id
            ORDER BY p.number ASC
        """, (recording_id, ws_proto_id))
        
        packets = cur.fetchall()
        
        # Key: (src_port, dst_port), Value: ZstdDecompressorObj
        streams = {}
        
        update_cur = conn.cursor()
        
        for pkt in packets:
            pid, num, payload, entropy, t_src, t_dst, u_src, u_dst = pkt
            
            src = t_src if t_src is not None else u_src
            dst = t_dst if t_dst is not None else u_dst
            
            if src is None or dst is None:
                continue
                
            # Check if this packet involves any of the relevant connections
            if tuple(sorted((src, dst))) not in relevant_connections:
                continue
            
            # Use directional key for decompression stream
            stream_key = (src, dst)
            
            if stream_key not in streams:
                dctx = zstd.ZstdDecompressor()
                streams[stream_key] = dctx.decompressobj()
            
            dobj = streams[stream_key]
            
            payload_bytes = bytes(payload)
            decompressed = None

            if payload_bytes.startswith(b'\x28\xb5\x2f\xfd'):
                try:
                    # Warning for low entropy
                    if entropy is not None and entropy < 6:
                        logging.warning(f"Packet {pid} (number {num}) has low entropy ({entropy}) but is being uncompressed.")
                    decompressed = dobj.decompress(payload_bytes)
                except Exception as e:
                    logging.warning(f"Decompression error for packet {pid} (number {num}): {e}")
            else:
                decompressed = payload_bytes

            if decompressed:
                try:
                    decoded_str = etf_decode(decompressed)
                    payload_to_write = decoded_str.encode('utf-8')
                    update_cur.execute(
                        "INSERT INTO packet_processing_tag (packet_id, step) VALUES (%s, %s)",
                        (pid, "websocket binary payload zstd decompressed and etf decoded")
                    )
                except Exception as decode_err:
                    logging.warning(f"ETF decode failed for packet {pid}: {decode_err}")
                    payload_to_write = decompressed

                update_cur.execute(
                    "UPDATE packet SET clear_application_payload = %s WHERE packet_id = %s",
                    (payload_to_write, pid)
                )
                
        conn.commit()
        update_cur.close()

    finally:
        cur.close()
