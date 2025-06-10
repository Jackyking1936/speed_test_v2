import subprocess
import socket
import pyshark
import binascii
import threading
import logging
from datetime import datetime
from my_logger import get_logger
from fubon_neo.sdk import FubonSDK, Order
from fubon_neo.constant import TimeInForce, OrderType, PriceType, MarketType, BSAction
import time
import json
import pandas as pd
import os

today = datetime.today()
today_str = datetime.strftime(today, "%Y%m%d")

logger = get_logger(name="pkt_logger", log_file=f"./log/pkt.log.{today_str}", log_level=logging.DEBUG)
cur_user_def = ""
order_time = ""
order_finish_time = ""
time_dict = {}

def list_all_interfaces():
    try:
        result = subprocess.check_output(['tshark', '-D'], encoding='utf-8')
        interfaces = result.strip().split('\n')
        for iface in interfaces:
            print(iface)
    except subprocess.CalledProcessError as e:
        logger.error(f"無法執行 tshark -D，請確認 tshark 已安裝並加入環境變數")
        logger.error(f"{e.output}")
    return interfaces

interfaces = list_all_interfaces()
if interfaces:
    try:
        idx = int(input("\n請輸入要監聽的介面編號： "))
        idx = idx-1
        interface_line = interfaces[idx]
        interface_fullname = interface_line.split('. ', 1)[1].split(' ', 1)[0]
        logger.info(f"{interface_fullname}")
    except (IndexError, ValueError):
        logger.error(F"無效的輸入")


# 自動抓出本機的 IPv4(非 127.0.0.1)
def get_local_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))  # 不會真的送資料
            return s.getsockname()[0]
    except Exception:
        return '127.0.0.1'

# 可自訂目標 IP
SERVER_IP = "203.75.89.49"
INTERFACE = interface_fullname

def packet_callback(pkt):
    global time_dict, cur_user_def
    logger.info("=" * 60)
    # logger.info(f"Layers: {pkt.layers}")
    logger.info(f"Length: {pkt.length}")
    logger.info(f"🕒 時間: {pkt.sniff_time}")
    # logger.info(f"📡 協定: {pkt.highest_layer}")

    try:
        logger.info(f"來源: {pkt.ip.src} → 目的: {pkt.ip.dst}")
    except AttributeError:
        pass

    if 'websocket' in pkt:
        try:
            payload = pkt.websocket.get('payload.text', '')
            fin_bit = pkt.websocket.get('websocket.fin', '')
            # payload_str = bytes.fromhex(payload.replace(':', '')).decode('utf-8', errors='ignore')
            if cur_user_def in payload and "_sign" in payload:
                print("!!!!!!!!!!!!!!!!!THIS IS ORDER PKT!!!!!!!!!!!!")
                time_dict[cur_user_def]['order_card_time'] = pkt.sniff_time
                logger.info(f"FIN_BIT: {fin_bit}")
                logger.info(f"💬 WebSocket Payload: {payload}")
            # else:
            #     print(f"{cur_user_def}, not critical pkt")
            #     print(f"{payload}")
        except Exception as e:
            logger.info(f"⚠️ 無法解析 WebSocket Payload: {e}")
    
    if 'tcp' in pkt:
        if hasattr(pkt.tcp, 'payload'):
            hex_payload = pkt.tcp.payload
            hex_str = hex_payload.replace(":", "").replace("\n", "")
            byte_data = binascii.unhexlify(hex_str)
            text = byte_data.decode("utf-8", errors="replace")

            if cur_user_def in text and "\"U\"" in text:
                print("!!!!!!!!!!!!!!!!!ACTIVE REPORT!!!!!!!!!!!!!!!!")
                if "\"ttst\":10" in text:
                    time_dict[cur_user_def]['TTST10'] = pkt.sniff_time
                    logger.info(f"TTST10 Time: {pkt.sniff_time}")
                    logger.info(f"TCP Payload: {text}")
                elif "\"ttst\":8" in text:
                    time_dict[cur_user_def]['TTST8'] = pkt.sniff_time
                    logger.info(f"TTST8 Time: {pkt.sniff_time}")
                    logger.info(f"TCP Payload: {text}")
                # else:
                #     print(f"{cur_user_def}, not critical pkt")
            elif cur_user_def in text and "\"tttk\"" in text:
                print("!!!!!!!!!!!!!!!!!FUNC RETURN!!!!!!!!!!!!!!!!!!")
                time_dict[cur_user_def]['FUNC'] = pkt.sniff_time
                logger.info(f"FUNC Time: {pkt.sniff_time}")
                logger.info(F"TCP Payload: {text}")
            # else:
            #     logger.info(f"TCP Payload: {text}")
            #     print(f"{cur_user_def}, not important TCP")

    # if hasattr(pkt, 'data'):
    #     try:
    #         logger.info(f"📦 Raw Payload: {pkt.data.data}")
    #     except AttributeError:
    #         logger.info(f"⚠️ data 層存在但沒有 data 欄位")


# 設定封包過濾條件：只抓目的 IP 為 TARGET_IP 的封包
display_filter = (
    f"ip.addr == {SERVER_IP}"
)

# 介面名稱請視你的系統調整，例如 'Wi-Fi', 'Ethernet', 'eth0'
capture = pyshark.LiveCapture(
    interface=INTERFACE,
    display_filter=display_filter
)

def pkt_fetch_start():
    logger.info(f"Display filter: {display_filter}")
    logger.info(f"擷取封包中（SERVER IP 為 {SERVER_IP}，Ctrl+C 可停止）")
    capture.apply_on_packets(packet_callback)

pkt_thread = threading.Thread(target=pkt_fetch_start, name="pkt")
pkt_thread.start()

time.sleep(2)
sdk = FubonSDK(30, 2, "ws://neoapi.fbs.com.tw/TASP/XCPXWS")

with open("info.json", "r") as file:
    user_info = json.load(file)

accounts = sdk.login(user_info['id'], user_info['pwd'], user_info['cert_path'], user_info['cert_pwd'])  # 需登入後，才能取得行情權限
if accounts.is_success:
    logger.info(accounts)
else:
    logger.error(f"Login failed, {accounts.message}")

def ms_diff_cal(col1, col2):
    col1 = pd.to_datetime(col1, format='%H:%M:%S.%f')
    col2 = pd.to_datetime(col2, format='%H:%M:%S.%f')

    # 計算毫秒差（以 timedelta 計算，再取毫秒）
    diff_col = (col2 - col1).dt.total_seconds() * 1000
    diff_col.round(3)
    return diff_col

# while True:
    # order_input = input("a)下單, b)show time c)結束：")

time.sleep(5)

order_input = "a"
order_num = 60
for i in range(order_num):
    order_time = datetime.now()
    hr_min_s = datetime.strftime(order_time, "%H%M%S")
    cur_user_def = f"WS{hr_min_s}"
    #建立委託單內容
    order = Order(
        buy_sell = BSAction.Buy,
        symbol = "2883",
        price = "15.85",
        quantity =  1000,
        market_type = MarketType.Common,
        price_type = PriceType.Limit,
        time_in_force= TimeInForce.ROD,
        order_type = OrderType.Stock,
        user_def = cur_user_def # optional field
    ) 

    time_dict[cur_user_def] = {}
    time_dict[cur_user_def]["order_time"] = order_time
    logger.info(f"[Order Start][{order_time}][{cur_user_def}]")
    func_start_time = datetime.now()
    res = sdk.stock.place_order(accounts.data[0], order)  #下單委託

    time_dict[cur_user_def]["func_start_time"] = func_start_time
    if res.is_success:
        order_finish_time = datetime.now()
        time_dict[cur_user_def]['order_finish_time'] = order_finish_time
        time_dict[cur_user_def]['Exg_time'] = datetime.strptime(f"{today.strftime('%Y-%m-%d')} {res.data.last_time}", "%Y-%m-%d %H:%M:%S.%f")
        time_dict[cur_user_def]['order_no'] = res.data.order_no
        time_diff = order_finish_time - order_time
        seconds = time_diff.total_seconds()
        if i == order_num-1:
            time.sleep(2)
            Rec_df = pd.DataFrame(time_dict)
            Rec_df = Rec_df.T
            # ['order_time', 'order_card_time', 'Exg_time', 'TTST8', 'FUNC', 'TTST10', 'order_finish_time']
            Rec_df = Rec_df[['order_no', 'order_time', 'order_card_time', 'Exg_time', 'TTST8', 'FUNC', 'TTST10', 'order_finish_time']]

            Rec_df['b4_card_lat'] = ms_diff_cal(Rec_df['order_time'], Rec_df['order_card_time'])
            Rec_df['af_card_lat'] = ms_diff_cal(Rec_df['order_card_time'], Rec_df['Exg_time'])
            Rec_df['TTST10_lat'] = ms_diff_cal(Rec_df['Exg_time'], Rec_df['TTST10'])
            Rec_df['FUNC_lat'] = ms_diff_cal(Rec_df['Exg_time'], Rec_df['FUNC'])
            Rec_df['af_FUNC'] = ms_diff_cal(Rec_df['FUNC'], Rec_df['order_finish_time'])
            Rec_df['total_lat'] = ms_diff_cal(Rec_df['order_time'], Rec_df['order_finish_time'])

            time_cols = Rec_df.select_dtypes(include='datetime').columns
            Rec_df[time_cols] = Rec_df[time_cols].apply(lambda col: col.dt.time)

            filename = f"Rec_{today_str}.csv"
            if os.path.exists(filename):
                Rec_df.to_csv(filename, mode='a', header=False, index=False)
            else:
                Rec_df.to_csv(filename, index=False)
    
    time.sleep(3)