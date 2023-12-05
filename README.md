## 设计

### 要求

<img src="C:\Users\梅某彦\AppData\Roaming\Typora\typora-user-images\image-20231105171857478.png" alt="image-20231105171857478" style="zoom: 67%;" />



### 内核



过滤与筛选方式：



protocol      icmp, tcp....

sip                1.1.1.1 / any

dip

sport

dport



信息交互

| 编码 | 含义                       |
| ---- | -------------------------- |
| 1    | 正常回复                   |
| 2    | 数据包，需要进行分析和转换 |
| 3    | 错误信息                   |
| 4    | 过滤信息                   |



模块：

<img src="C:\Users\梅某彦\AppData\Roaming\Typora\typora-user-images\image-20231105175854203.png" alt="image-20231105175854203" style="zoom:67%;" />

截获数据包，分析出IP层信息，对其进行过滤，通过过滤的数据包将整个包发送给应用层

**此处需要注意：**
1、数据包要足够大

2、复制方法：

skb  head->tail



信息交互模块

数据包截获模块

数据包解析模块

过滤模块



### 应用

UI

<img src=".\image\UI.png" alt="UI" style="zoom:15%;" />

选项：

IP过滤器，长度限制器，协议过滤器

滑动窗口：

每一个元素显示数据的初步内核信息，点击查看内核详细信息：

链路层、物理层信息



应用层功能：

使用scapy解析数据包，显示数据包详细信息

发送过滤规则：
增加一个过滤页面进行过滤设置



proto

sip,dip,sport,dport



过滤信息传递：

增添一个新的数据结构

| 名字  | 大小               | 含义     |
| ----- | ------------------ | -------- |
| proto | int                | 协议     |
| sip   | unsigned char [16] | 源IP     |
| sport | uint16             | 源端口   |
| dip   | unsigned char [16] | 目标IP   |
| dport | uint16             | 目标端口 |




功能、界面丰富：

1、开始嗅探和停止嗅探时要有提示信息，需要看得出变化

2、详细信息页面可以加一个展示原始二进制数据的功能

3、可以加一个检测流量的功能







