import socket
import os
import struct
from scapy.all import *
from scapy.layers.l2 import Ether

# 定义Netlink socket的相关常量
NETLINK_ROUTE = 0  # Netlink路由协议
NLMSG_NOOP = 1  # 没有操作
NLMSG_ERROR = 2  # 错误
NLMSG_DONE = 3  # 完成
NLMSG_OVERRUN = 4  # 超出

# 创建Netlink socket
sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 17)

# 定义数据包结构
fmt = "IHHII"
nlmsg_hdr = struct.Struct(fmt)

# 绑定到Netlink socket
sock.bind((0, 0))

# 准备发送的数据
data_to_send = b"Hello from Python"

# 创建Netlink消息头
header = nlmsg_hdr.pack(nlmsg_hdr.size + len(data_to_send), NLMSG_NOOP, 0, 123, os.getpid())

# 发送消息
sock.send(header + data_to_send)

# 接收和处理消息
while True:
    data = sock.recv(65535)
    length, msg_type, flags, seq, pid = nlmsg_hdr.unpack(data[:nlmsg_hdr.size])

    # 处理消息类型
    if msg_type == NLMSG_DONE:
        print("Received done message")
        break
    elif msg_type == NLMSG_ERROR:
        print("Received error message")
        break
    else:
        # 处理其他类型的消息
        # 在这里可以根据需要处理接收到的消息
        print("Received message:", data[nlmsg_hdr.size:])
        try:

            pc=Ether(data[nlmsg_hdr.size:])
            pc.show()
        except:
            print("wrong")

