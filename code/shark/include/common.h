#include <linux/kernel.h>  
#include <linux/init.h>  
#include <linux/module.h>  
#include <linux/version.h>  
#include <linux/string.h>  
#include <linux/kmod.h>  
#include <linux/vmalloc.h>  
#include <linux/workqueue.h>  
#include <linux/spinlock.h>  
#include <linux/socket.h>  
#include <linux/net.h>  
#include <linux/in.h>  
#include <linux/skbuff.h>  
#include <linux/ip.h>  
#include <linux/tcp.h>  
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/netfilter.h>  
#include <linux/netfilter_ipv4.h>  
#include <linux/icmp.h>  
#include <net/sock.h>  
#include <asm/uaccess.h>  
#include <asm/unistd.h>  



void addr_inet(unsigned int ip,char * str);
void getPort(struct sk_buff *skb, struct iphdr *hdr, unsigned int *src_port, unsigned int *dst_port);
void print_binary(const void *data, size_t size,uint8_t * dst);
