import PySimpleGUI as sg
import time
import threading

import socket
import os
import struct
from scapy.all import *
from scapy.layers.l2 import Ether
run=False
inner='1'
text=sg.Text(inner)
totalpacket=0

list_view = sg.Listbox(['item 1', 'item 2'])
# -----------初始化-------------
# 定义Netlink socket的相关常量
NETLINK_TEST =17
NETLINK_ROUTE = 0  # Netlink路由协议
NLMSG_RSP = 1  # 没有操作
NLMSG_PACKET = 2  # 错误
NLMSG_ERROR = 3  # 完成
NLMSG_RULE = 4  # 超出
# 创建Netlink socket
sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 17)
# 定义数据包结构
fmt = "IHHII"
filter_fmt="I 16s H 16s H"
nlmsg_hdr = struct.Struct(fmt)
filter_data = struct.Struct(filter_fmt)
# 绑定到Netlink socket
sock.bind((0, 0))
# 准备发送的数据
data_to_send = b"Hello from Python"
# 创建Netlink消息头
header = nlmsg_hdr.pack(nlmsg_hdr.size + len(data_to_send), NLMSG_RSP, 0, 123, os.getpid())


f_protocol=0
f_sip=''
f_dip=''
f_sport=0
f_dport=0
packets=[] #接收到的数据包
rows = []  #展示的数据包信息

def sendData(type,data=b"Hello from Python"):
    #发送信息给netlink内核
    header = nlmsg_hdr.pack(nlmsg_hdr.size + len(data_to_send), type, 0, 123, os.getpid())
    sock.send(header + data)
    return 0

def getNetlink(window):
    #获取来自内核netlink的数据
    global packets,rows,run,totalpacket
    print("setting link")
    sendData(type=NLMSG_RSP)

    while True:
        if run==False:
            print("current task end")
            break
        data = sock.recv(65535)
        length, msg_type, flags, seq, pid = nlmsg_hdr.unpack(data[:nlmsg_hdr.size])

        # 处理消息类型
        if msg_type == NLMSG_RSP:
            print("Received done message")
        elif msg_type == NLMSG_ERROR:
            print("Received error message")
            break
        elif msg_type ==NLMSG_PACKET :
        #elif msg_type == NLMSG_PACKET :
            # 接收到数据包
            print("Received message:", data[nlmsg_hdr.size:])
            try:
                pc = Ether(data[nlmsg_hdr.size:])
                #数据包
                packets.append(pc)
                #显示信息拆解
                src=pc['IP'].src
                dst=pc['IP'].dst
                proto=pc['IP'].proto
                #format_str = '{:^5}{:^25}{:^25}{:<8}'  # 格式化字符串 编号 sip dip proto
                msg = [totalpacket,src,dst,proto]
                rows.append(msg)
                #将show的信息dump出来
                totalpacket+=1
                window['-TABLE-'].update(values=rows, scroll_to_index=totalpacket)
            except Exception as error:
                print(error)
        else :
            print("something else")


def clear_storage(window):
    #清空当前的列表
    global packets,rows,totalpacket
    packets.clear()
    rows.clear()
    totalpacket=0
    window['-TABLE-'].update(values=rows)



def long_time_work(window):
    global inner,text
    for i in range(10):
        time.sleep(1)
        window.write_event_value('任务进度', i)
        inner+='1'
        text.update(inner)

    window.write_event_value('任务结束', '')


def detail_window():
    #数据包详细信息框弹窗
    global f_dport,f_dip,f_sip,f_sport,f_protocol
    proto=sg.Input(size=(200,20),key='-PROTO-',default_text=f_protocol)
    sip = sg.Input(size=(200,20),key='-SIP-',default_text=f_sip)
    dip = sg.Input(size=(200,20),key='-DIP-',default_text=f_dip)
    sport = sg.Input(size=(50,20),key='-SPORT-',default_text=f_sport)
    dport = sg.Input(size=(50,20),key='-DPORT-',default_text=f_dport)
    layout=[[sg.Text('Protocol')],[proto],
            [sg.Text('Source')],[sg.Text('ip:')],
            [sip]
        ,   [sg.Text('port:')],
            [sport],
            [sg.Text('Destination')],[sg.Text('ip:')],
            [dip],
            [sg.Text('port:')],
            [dport],
            [sg.B('OK'),sg.B('Cancel')]]
    window=sg.Window("Filter",layout,size=(400,500))
    while True:
        event, values = window.read(timeout=100)
        if event == sg.WIN_CLOSED:
            break
        if event == 'OK':
            #提交过滤内容
            f_protocol=int(values['-PROTO-'])
            f_sip=values['-SIP-']
            f_dip=values['-DIP-']
            f_sport=values['-SPORT-']
            f_dport=values['-DPORT-']
            data=filter_data.pack(f_protocol,f_sip,f_sport,f_dip,f_dport)
            print(data)
            sendData(NLMSG_RULE,data)
        if event == 'Cancel':
            #取消
            break


    window.close()

def main_window():
    #创建主窗口
    sg.set_options(font=("Arial Bold", 14))
    pattern=sg.Text(
        text='......',
        key='-PATTERN-'

    )
    #开始和停止按钮
    upButtons=[sg.B('start'),sg.B('stop'),sg.B('clear'),sg.B('filter'),pattern]
    #过滤信息

    #myshark数据包显示窗口
    toprow = ['S.No.', 'Name', 'Age', 'Marks']
    #使用listbox显示更加平滑
    tbl1 = sg.Listbox(values=rows,
                     key='-TABLE-',
                     enable_events=True,
                     expand_x=True,
                     expand_y=True,
                     )
    detail = sg.Multiline(
        key='-DETAIL-',
        enable_events=True,
        expand_x=True,
        expand_y=True

    )

    #详细信息显示
    layout = [[upButtons],[tbl1],[sg.B('mad'),sg.Text('Packet Detail')],[detail]]
    window = sg.Window("MyShark", layout,size=(600,700), resizable=True)
    return window



def main():
    global run
    window=main_window()

    while True:
        event, values = window.read(timeout=100)

        if event == sg.WIN_CLOSED:
            break
        if event == 'start':
            window['-PATTERN-'].update(value='working...')
            thread = threading.Thread(target=getNetlink,args=(window,),  daemon=True)
            if run==False:
                run=True
                thread.start()
        if event == 'stop' :
            window['-PATTERN-'].update(value='......')
            run=False
        if event == 'clear':
            clear_storage(window)
        if event == 'filter':
            thread = threading.Thread(target=detail_window(), daemon=True)
            thread.start()

        #获取listbox点击信息
        for row in values['-TABLE-'] :
            if packets !=[] and rows!=[]:
                print(row[0])
                window['-DETAIL-'].update(value=packets[row[0]].show(dump=True))



    window.close()

if __name__ == '__main__':

    main()

