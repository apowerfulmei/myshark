## 设计

### 要求

<img src="C:\Users\梅某彦\AppData\Roaming\Typora\typora-user-images\image-20231105171857478.png" alt="image-20231105171857478" style="zoom: 67%;" />



### 内核

数据结构：

协议类型：TCP、IP、ICMP、UDP、

源IP、端口

目的IP、端口

长度

raw data





模块：

<img src="C:\Users\梅某彦\AppData\Roaming\Typora\typora-user-images\image-20231105175854203.png" alt="image-20231105175854203" style="zoom:67%;" />

信息交互模块

数据包截获模块

数据包解析模块

过滤模块



### 应用

UI

选项：

IP过滤器，长度限制器，协议过滤器

滑动窗口：

每一个元素显示数据的初步内核信息，点击查看内核详细信息：

链路层、物理层信息







