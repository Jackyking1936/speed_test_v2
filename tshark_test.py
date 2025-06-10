import pyshark

INTERFACE = 'ens4'

def packet_callback(pkt):
    print("="*60)
    print(f"🕒 時間: {pkt.sniff_time}")
    print(f"📡 協定: {pkt.highest_layer}")

    try:
        print(f"來源: {pkt.ip.src} → 目的: {pkt.ip.dst}")
    except AttributeError:
        pass

    if 'http' in pkt:
        print("🌐 HTTP 資訊:")
        print(pkt.http)

    if 'websocket' in pkt:
        try:
            payload = pkt.websocket.get('payload', '')
            payload_str = bytes.fromhex(payload.replace(':', '')).decode('utf-8', errors='ignore')
            print("💬 WebSocket Payload:", payload_str)
        except Exception as e:
            print("⚠️ 無法解析 WebSocket Payload:", e)

    # ✅ 安全檢查 data 層是否存在
    if hasattr(pkt, 'data'):
        try:
            print("📦 Raw Payload:", pkt.data.data)
        except AttributeError:
            print("⚠️ data 層存在但沒有 data 欄位")


# 介面名稱請視你的系統調整，例如 'Wi-Fi', 'Ethernet', 'eth0'
capture = pyshark.LiveCapture(interface=INTERFACE)

print("🚀 使用 callback 擷取封包中（Ctrl+C 可停止）")
capture.apply_on_packets(packet_callback)

