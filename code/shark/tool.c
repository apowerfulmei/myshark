#include "common.h"


void addr_inet(unsigned int ip,char * str)
{
	sprintf(str,"%d.%d.%d.%d",(ip>>24)&0xff,(ip>>16)&0xff,(ip>>8)&0xff,ip&0xff);
}
void getPort(struct sk_buff *skb, struct iphdr *hdr, unsigned int *src_port, unsigned int *dst_port){
	struct tcphdr *tcpHeader;
	struct udphdr *udpHeader;
	switch(hdr->protocol){
		case IPPROTO_TCP:
			//printk("TCP protocol\n");
			tcpHeader = (struct tcphdr *)(skb->data + (hdr->ihl * 4));
			*src_port = ntohs(tcpHeader->source);
			*dst_port = ntohs(tcpHeader->dest);
			break;
		case IPPROTO_UDP:
			//printk("UDP protocol\n");
			udpHeader = (struct udphdr *)(skb->data + (hdr->ihl * 4));
			*src_port = ntohs(udpHeader->source);
			*dst_port = ntohs(udpHeader->dest);
			break;
		case IPPROTO_ICMP:
		default:
			//printk("other protocol\n");
			*src_port = 0;
			*dst_port = 0;
			break;
	}
}
void print_binary(const void *data, size_t size,uint8_t * dst) {
	//打印和复制
    const uint8_t *byte_data = (const uint8_t *)data;
	size_t i=0;
	if(size>8192){
		printk("too big %x",size);
		return;
	}

    for (i = 0; i < size; ++i) {
        uint8_t byte = byte_data[i];
		dst[i]=byte;
        //printk("%x",byte);
    }

}