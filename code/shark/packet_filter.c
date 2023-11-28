#include "common.h"
	  
MODULE_LICENSE("GPL");  
MODULE_AUTHOR("xsc");  
#define NETLINK_TEST	17
#define NLMSG_RSP       1  
#define NLMSG_PACKET    2  
#define NLMSG_ERROR     3  
#define NLMSG_RULE      4 
#define NLMSG_STOP      5 
#define TCP_N           6
#define UDP_N           17
#define ICMP_N          1
static struct nf_hook_ops nfho;  
static struct sock *nlsk = NULL;
static struct nf_hook_ops nfho;  
static struct nf_hook_ops natop_in;
static struct nf_hook_ops natop_out; 
int pid=-1;
int start=0;


int nltest_ksend(void *info,int rlen,uint16_t type )
{
	char reply[256];
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	int retval;
	

	skb = nlmsg_new(rlen, GFP_ATOMIC);
	if (skb == NULL) {
		printk("alloc reply nlmsg skb failed!\n");
		return -1;
	}
	printk("pid:%d",pid);

	nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(rlen) - NLMSG_HDRLEN, 0);
	nlh->nlmsg_type=type;
	memcpy(NLMSG_DATA(nlh), info, rlen);
	printk("[kernel space] nlmsglen = %d\n", nlh->nlmsg_len);

	//NETLINK_CB(skb).pid = 0;
	NETLINK_CB(skb).dst_group = 0;


	printk("[kernel space] skb->data send to user: '%s'\n", (char *) NLMSG_DATA(nlh));

	retval = netlink_unicast(nlsk, skb, pid, MSG_DONTWAIT);
	printk("[kernel space] netlink_unicast return: %d\n", retval);

	return 0;
}
struct F_msg{
    int proto;
    unsigned char sip[16];
    uint16_t sport;
    unsigned char dip[16];
    uint16_t dport;
}filter_rule={-1,"any",-1,"any",-1};

uint16_t dealMsg(uint16_t msg_type,int skb_pid,void *data)
{
	switch(msg_type)
	{
		case NLMSG_RSP :
		//开始
		start=1;
		pid=skb_pid;
		printk("finish link build with %d",pid);
		return NLMSG_RSP;

		case NLMSG_RULE :
		//接收过滤规则内容
		filter_rule=(struct F_msg *)data;

		return NLMSG_RULE;

		case NLMSG_STOP :
		//嗅探器停止
		start=0;
		pid=-1;
		return NLMSG_STOP;

		
	}
	return NLMSG_RSP;
}


void nltest_krecv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = NULL;
	printk("%x\n",skb);
	//接收数据
	void *data;
	char msg[256];
	nlh = nlmsg_hdr(skb);
	if ((nlh->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nlh->nlmsg_len)) {
		printk("Illegal netlink packet!\n");
		return;
	}
	//获取数据
	data =  NLMSG_DATA(nlh);
	//analysis the msg
	char buf[256];
	int id;
	unsigned int sip;
	char tid;//rule/nat/connection
	memset(msg,0,256);
	uint16_t type= nlh->nlmsg_type;
	printk("to send back %s\n",msg);
	nltest_ksend("hi",3,dealMsg(type,nlh->nlmsg_pid,data));
}

struct netlink_kernel_cfg nltest_cfg = {
	0,	//groups
	0,	//flags
	nltest_krecv,	//input
	NULL,	//cb_mutex
	NULL,	//bind
	NULL,	//unbind
	NULL,	//compare
};

unsigned int hook_func(unsigned int hooknum,  
	                      struct sk_buff *skb,  
	                      const struct net_device *in,  
	                      const struct net_device *out,  
	                      int (*okfn)(struct sk_buff *))  
{  
	if(start==0)
		return NF_ACCEPT;
    int i;
	char msg[256];
    unsigned int sport, dport;
    unsigned int sip, dip;
	unsigned char smac[10],dmac[10];
	uint8_t packet[8192];
	//此处packet要足够大，不然会引起问题
    char saddr[20];
	char daddr[20];
	char proto[10];

    int isMatch = 0, isLog = 1;  // 默认记录日志
	//ether段
	struct ethhdr *eth;
    eth = (struct ethhdr *)skb_mac_header(skb);
	    // 提取源 MAC 地址
    printk(KERN_INFO "Source MAC Address: %pM\n", eth->h_source);

    // 提取目标 MAC 地址
    printk(KERN_INFO "Destination MAC Address: %pM\n", eth->h_dest);
    printk(KERN_INFO "skb->len: %u\n", skb->len); // 数据包长度
    printk(KERN_INFO "skb->protocol: %04X\n", skb->protocol); 
	printk(KERN_INFO "skb->protocol: %X\n", *skb->data); 
	printk(KERN_INFO "skb->protocol: %X\n", *(skb->head+1)); 
	int totallen=skb->len+14;
	unsigned char *data = skb->data;
	unsigned char *head=data-14;
    unsigned char *tail_data = data + skb->len;

    // 打印提取到的数据
    //printk(KERN_INFO "Data from skb->data to skb->tail: %.*s\n", (int)(tail_data - data), data);
	//memcpy(packet,head,totallen);
	print_binary(head,totallen,packet);
	// memcpy(smac, eth->h_source, ETH_ALEN);
	// memcpy(dmac, eth->h_dest, ETH_ALEN);
	// printk("%s %s",smac,dmac);
    // 初始化
	struct iphdr *header = ip_hdr(skb);
	
	getPort(skb,header,&sport,&dport);
    sip = ntohl(header->saddr);
    dip = ntohl(header->daddr);
	addr_inet(sip,saddr);
	addr_inet(dip,daddr);    
    printk("recv %s %s %u %u %d\n",saddr,daddr,sport,dport,header->protocol);
    // 查询是否有已有连接

    printk("pipei\n");
    // 匹配规则
    // for(i=1;i<=curn;i++)
    // {
    // 	if(rules[i].work==-1) continue;
    // 	if(!(isIPMatch(sip,rules[i].src,rules[i].smask))&&isIPMatch(dip,rules[i].dst,rules[i].dmask))
    // 		continue;
    // 	if(!((rules[i].sport==-1||sport==rules[i].sport)&&(rules[i].dport==-1||dport==rules[i].dport)))
    // 		continue;
    // 	if(!(header->protocol==rules[i].protocol))
    // 		continue;
    // 	isMatch=i;
    // 	break;
    // }

    //
    // if(isMatch) { // 匹配到了一条规则
    // 	action = (rules[isMatch].opr=='y') ? NF_ACCEPT : NF_DROP;

    // }
    // // 更新连接池
    // if(action == NF_ACCEPT) {
    //     addConn(sip,dip,sport,dport,header->protocol);
    // }
	sprintf(msg,"%s %s %u %u %d\n",saddr,daddr,sport,dport,header->protocol);
	if(pid!=-1)
		nltest_ksend(packet,totallen,NLMSG_PACKET);
    return NF_ACCEPT;
}  
static int kexec_test_init(void)  
{  
	nlsk = netlink_kernel_create(&init_net, NETLINK_TEST, &nltest_cfg);
	if (!nlsk) {
		printk("can not create a netlink socket\n");
		return -1;
	}
	printk("netlink_kernel_create() success, nlsk = %p\n", nlsk);
	nfho.hook = (nf_hookfn *)hook_func;  
	nfho.pf = PF_INET;  
	nfho.hooknum = NF_INET_LOCAL_IN;  
	nfho.priority = NF_IP_PRI_FIRST;  
	nf_register_net_hook(&init_net, &nfho);  
	printk("kexec test start ...\n");  
	  
	    // nfho.hook = (nf_hookfn *)nltest_krecv;  
	    // nfho.pf = PF_INET;  
	    // nfho.hooknum = NF_INET_LOCAL_OUT;  
	    // nfho.priority = NF_IP_PRI_FIRST;  
	      
	    // nf_register_net_hook(&init_net, &nfho);                                 /// 注册一个钩子函数  
	  
	    return 0;  
}  
	  
static void kexec_test_exit(void)  
{  
	    // printk("kexec myfirewall exit ...\n");  
	nf_unregister_net_hook(&init_net,&nfho);  
	netlink_kernel_release(nlsk);
}  
  
module_init(kexec_test_init);  
module_exit(kexec_test_exit);  
