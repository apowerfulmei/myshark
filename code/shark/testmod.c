#include "common.h"


#define NETLINK_TEST	17
#define TCP_N 6
#define UDP_N 17
#define ICMP_N 1

static struct sock *nlsk = NULL;
static struct nf_hook_ops nfho;  
static struct nf_hook_ops natop_in;
static struct nf_hook_ops natop_out;
struct file *log;   //日志文件
mm_segment_t fs;
loff_t pos;
int curn;        //当前规则数
int cura;        //当前nat状态
int curc;        //当前状态表
unsigned int natport=666;
unsigned int natip=40962; //10.0.0.2
/*数据结构定义--------------------------------------------------------------------------------------------*/
struct rule {
	int id;
	int work;         
	unsigned int src;
	unsigned int smask;
	unsigned int dst;
	unsigned int dmask;
	unsigned int sport;
	unsigned int dport;
	int protocol;
	char opr;
	char log;
}rules[2048];


struct NATRecord { // NAT 记录 or 规则(源IP端口转换)
	int id;
	int work;
    unsigned int saddr; // 记录：原始IP | 规则：原始源IP
    unsigned int daddr; // 记录：转换后的IP | 规则：NAT 源IP
    unsigned short sport; // 记录：原始端口 | 规则：最小端口范围
    unsigned short dport; // 记录：转换后的端口 | 规则：最大端口范围
   	unsigned short now;   //当前使用的端口
}nats[2048];

struct conn {
	int id;
	unsigned int saddr;
	unsigned int daddr;
	unsigned int sport;
	unsigned int dport;
	int protocol;
	struct NatRecord nat;

}conns[2048];

/*数据结构定义--------------------------------------------------------------------------------------------*/








/*工具函数--------------------------------------------------------------------------------------------*/
void addr_inet(unsigned int ip,char * str)
{
	sprintf(str,"%d.%d.%d.%d",(ip>>24)&0xff,(ip>>16)&0xff,(ip>>8)&0xff,ip&0xff);
}
void num_proto(unsigned int proto,char * str)
{
	switch(proto)
	{
		case TCP_N:
		strcpy(str,"tcp");
		break;
		case UDP_N:
		strcpy(str,"udp");
		break;
		case ICMP_N:
		strcpy(str,"icmp");
		default:
		break;
	}
	return;
}
void loadbuf_to_rule(char * buf)
{
	//将buf中的内容填入rule
	curn++;
	rules[curn].id=curn;
	rules[curn].work=0;
	sscanf(buf,"%u %u %u %u %u %u %u %c %c",&rules[curn].src,&rules[curn].smask,&rules[curn].dst,&rules[curn].dmask,&rules[curn].sport,&rules[curn].dport,&rules[curn].protocol,&rules[curn].opr,&rules[curn].log);
	printk("new rule: %s",buf);
	return;
}

void loadrule_to_buf(int id,char * buf)
{
	//将rule中的内容填入buf
	char saddr[20];
	char daddr[20];
	char proto[10];
	addr_inet(rules[id].src,saddr);
	addr_inet(rules[id].dst,daddr);
	num_proto(rules[id].protocol,proto);
	sprintf(buf,"%d %s %u %s %u %u %u %s %c %c\n",id,saddr,rules[curn].smask,daddr,rules[id].dmask,rules[id].sport,rules[id].dport,proto,rules[id].opr,rules[id].log);
	printk("rule to buf %s",buf);
}

unsigned int inet_addr(char *str)   
{   
    int a,b,c,d;   
	char arr[4];   
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);   
	arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;   
	return *(unsigned int*)arr;   
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



bool isIPMatch(unsigned int ipl, unsigned int ipr, unsigned int mask) {
	return (ipl & 0xffffffff<<(32-mask)) == (ipr & 0xffffffff<<(32-mask));
}

void load_allrule(char * buf)
{
	int i;
	char temp[64];
	for(i=1;i<=curn;i++)
	{
		if(rules[i].work>=0)
		{

			loadrule_to_buf(i,temp);
			printk("%d rule %s\n",i,temp);
			strcat(buf,temp);
		}
		
	}
}

void load_allnat(char * buf)
{
	int i;
	char temp[64];
	char saddr[20];
	char daddr[20];
	char proto[10];

	for(i=1;i<=cura;i++)
	{
		if(nats[i].work>=0)
		{
			addr_inet(nats[i].saddr,saddr);
			addr_inet(nats[i].daddr,daddr);
			sprintf(temp,"%d %s %u ---> %s %u\n",nats[i].id,saddr,nats[i].sport,daddr,nats[i].dport);		
			strcat(buf,temp);
		}
	}
}
/*工具函数--------------------------------------------------------------------------------------------*/



/*状态表--------------------------------------------------------------------------------------------*/
int hasConn(unsigned int sip,unsigned int dip,unsigned int sport,unsigned int dport)
{
	//查找状态
	int i;
	for(i=1;i<=curc;i++)
	{
		if(conns[i].saddr==sip&&conns[i].daddr==dip&&conns[i].sport==sport&&conns[i].dport==dport)
			return i;
	}
	return -1;

}
void addConn(unsigned int sip, unsigned int dip, unsigned short sport, unsigned short dport,unsigned int protocol){
	//添加连接状态
	curc++;
	conns[curc].saddr=sip;
	conns[curc].daddr=dip;
	conns[curc].sport=sport;
	conns[curc].dport=dport;
	conns[curc].protocol=protocol;
	return;
}
void load_allconc(char * buf)
{
	int i;
	char temp[64];
	char saddr[20];
	char daddr[20];
	char proto[10];

	for(i=1;i<=curc;i++)
	{
		if(nats[i].work>=0)
		{
			addr_inet(conns[i].saddr,saddr);
			addr_inet(conns[i].daddr,daddr);
			num_proto(conns[i].protocol,proto);
			sprintf(temp,"%s %u <-%s-> %s %u\n",saddr,nats[i].sport,proto,daddr,nats[i].dport);		
			strcat(buf,temp);
		}
	}
}




/*状态表--------------------------------------------------------------------------------------------*/


/*NAT相关----------------------------------------------------------------------------------------------------*/

unsigned int add_nat(unsigned int saddr,unsigned int sport)
{
	//IP,端口,协议.掩码
	//添加一条nat状态
	cura++;
	nats[cura].work=0;
	nats[cura].id=cura;
	nats[cura].saddr=saddr;
	nats[cura].sport=sport;
	nats[cura].daddr=natip+cura;
	nats[cura].dport=natport+cura;

	return cura;
}
int find_nat(unsigned int saddr,unsigned int sport)
{
	int i;
	for(i=1;i<=cura;i++)
	{
		if(nats[i].saddr==saddr&&nats[i].sport==sport)
			return i;
	}
	return -1;
}

unsigned int nat_in(unsigned int hooknum,  
	                      struct sk_buff *skb,  
	                      const struct net_device *in,  
	                      const struct net_device *out,  
	                      int (*okfn)(struct sk_buff *))
{
	//对输入的数据包进行nat转换
    unsigned int sport, dport;
    unsigned int sip, dip;
    unsigned int  proto;
    struct tcphdr *tcpHeader;
    struct udphdr *udpHeader;
    int hdr_len, tot_len;
    // 初始化
    struct iphdr *header = ip_hdr(skb);
    getPort(skb,header,&sport,&dport);
    sip = ntohl(header->saddr);
    dip = ntohl(header->daddr);
    proto = header->protocol;
    // 查连接池 NAT_TYPE_DEST
    int conn = hasConn(sip, dip, sport, dport);
    if(conn == -1) { // 不应出现连接表中不存在的情况
        printk(KERN_WARNING "[fw nat] (in)get a connection that is not in the connection pool!\n");
        return NF_ACCEPT;
    }

    // 转换目的地址+端口
    int rd=find_nat(sip,sport);
    //if(rd==-1)
    header->daddr = htonl(nats[rd].daddr);
    hdr_len = header->ihl * 4;
    tot_len = ntohs(header->tot_len);
    header->check = 0;
    header->check = ip_fast_csum(header, header->ihl);
    switch(proto) {
        case TCP_N:
            tcpHeader = (struct tcphdr *)(skb->data + (header->ihl * 4));
            tcpHeader->dest = htons(nats[rd].dport);
            tcpHeader->check = 0;
            skb->csum = csum_partial((unsigned char *)tcpHeader, tot_len - hdr_len, 0);
            tcpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                        tot_len - hdr_len, header->protocol, skb->csum);
            break;
        case UDP_N:
            udpHeader = (struct udphdr *)(skb->data + (header->ihl * 4));
            udpHeader->dest = htons(nats[rd].dport);
            udpHeader->check = 0;
            skb->csum = csum_partial((unsigned char *)udpHeader, tot_len - hdr_len, 0);
            udpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                        tot_len - hdr_len, header->protocol, skb->csum);
            break;
        case ICMP_N:
        default:
            break;
    }
    return NF_ACCEPT;

}
unsigned int nat_out(unsigned int hooknum,  
	                      struct sk_buff *skb,  
	                      const struct net_device *in,  
	                      const struct net_device *out,  
	                      int (*okfn)(struct sk_buff *))
{
    unsigned int sport, dport;
    unsigned int sip, dip;
    unsigned int  proto;
    struct tcphdr *tcpHeader;
    struct udphdr *udpHeader;
    int hdr_len, tot_len;
    // 初始化
    struct iphdr *header = ip_hdr(skb);
    getPort(skb,header,&sport,&dport);
    sip = ntohl(header->saddr);
    dip = ntohl(header->daddr);
    proto = header->protocol;
    // 查连接池 NAT_TYPE_DEST
    int conn = hasConn(sip, dip, sport, dport);
    if(conn == -1) { // 不应出现连接表中不存在的情况
        printk(KERN_WARNING "[fw nat] (in)get a connection that is not in the connection pool!\n");
        return NF_ACCEPT;
    }
    int rd=find_nat(sip,sport);
    if(rd==-1)
    {
    	//建立新的nat
    	printk("set a new nat\n");
    	rd=add_nat(sip,sport);

    }
    header->saddr = htonl(nats[rd].daddr);
    hdr_len = header->ihl * 4;
    tot_len = ntohs(header->tot_len);
    header->check = 0;
    header->check = ip_fast_csum(header, header->ihl);
    switch(proto) {
        case TCP_N:
            tcpHeader = (struct tcphdr *)(skb->data + (header->ihl * 4));
            tcpHeader->source = htons(nats[rd].dport);
            tcpHeader->check = 0;
            skb->csum = csum_partial((unsigned char *)tcpHeader, tot_len - hdr_len, 0);
            tcpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                        tot_len - hdr_len, header->protocol, skb->csum);
            break;
        case UDP_N:
            udpHeader = (struct udphdr *)(skb->data + (header->ihl * 4));
            udpHeader->source = htons(nats[rd].dport);
            udpHeader->check = 0;
            skb->csum = csum_partial((unsigned char *)udpHeader, tot_len - hdr_len, 0);
            udpHeader->check = csum_tcpudp_magic(header->saddr, header->daddr,
                                        tot_len - hdr_len, header->protocol, skb->csum);
            break;
        case ICMP_N:
        default:
            break;
    }
    return NF_ACCEPT;


}

/*NAT相关----------------------------------------------------------------------------------------------------*/




/*filter相关------------------------------------------------------------------------------------------------------------*/


unsigned int DEFAULT_ACTION = NF_ACCEPT;

unsigned int hook_func(unsigned int hooknum,  
	                      struct sk_buff *skb,  
	                      const struct net_device *in,  
	                      const struct net_device *out,  
	                      int (*okfn)(struct sk_buff *))  
{  

    int conn,i;
    unsigned int sport, dport;
    unsigned int sip, dip, action = DEFAULT_ACTION;
    char saddr[20];
	char daddr[20];
	char proto[10];

    int isMatch = 0, isLog = 1;  // 默认记录日志
    // 初始化
	struct iphdr *header = ip_hdr(skb);
	getPort(skb,header,&sport,&dport);
    sip = ntohl(header->saddr);
    dip = ntohl(header->daddr);
	addr_inet(sip,saddr);
	addr_inet(dip,daddr);    
    printk("recv %s %s %u %u %d\n",saddr,daddr,sport,dport,header->protocol);
    // 查询是否有已有连接
    conn = hasConn(sip, dip, sport, dport);
    printk("conn %d\n",conn);
    if(conn != -1) {

        return NF_ACCEPT;
    }
    printk("pipei\n");
    // 匹配规则
    for(i=1;i<=curn;i++)
    {
    	if(rules[i].work==-1) continue;
    	if(!(isIPMatch(sip,rules[i].src,rules[i].smask))&&isIPMatch(dip,rules[i].dst,rules[i].dmask))
    		continue;
    	if(!((rules[i].sport==-1||sport==rules[i].sport)&&(rules[i].dport==-1||dport==rules[i].dport)))
    		continue;
    	if(!(header->protocol==rules[i].protocol))
    		continue;
    	isMatch=i;
    	break;
    }

    //
    if(isMatch) { // 匹配到了一条规则
    	action = (rules[isMatch].opr=='y') ? NF_ACCEPT : NF_DROP;

    }
    // 更新连接池
    if(action == NF_ACCEPT) {
        addConn(sip,dip,sport,dport,header->protocol);
    }
    return action;
}  


/*filter相关------------------------------------------------------------------------------------------------------------*/





/*交互-------------------------------------------------------------------------------------------------------------*/

int nltest_ksend(char *info, int pid)
{
	char reply[256];
	int rlen;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	int retval;
	sprintf(reply, "NLTEST Reply for '%s'", info);
	rlen = strlen(reply) + 1;

	skb = nlmsg_new(rlen, GFP_ATOMIC);
	if (skb == NULL) {
		printk("alloc reply nlmsg skb failed!\n");
		return -1;
	}

	nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(rlen) - NLMSG_HDRLEN, 0);
	memcpy(NLMSG_DATA(nlh), reply, rlen);
	printk("[kernel space] nlmsglen = %d\n", nlh->nlmsg_len);

	//NETLINK_CB(skb).pid = 0;
	NETLINK_CB(skb).dst_group = 0;

	printk("[kernel space] skb->data send to user: '%s'\n", (char *) NLMSG_DATA(nlh));

	retval = netlink_unicast(nlsk, skb, pid, MSG_DONTWAIT);
	printk("[kernel space] netlink_unicast return: %d\n", retval);
	return 0;
}





void nltest_krecv(struct sk_buff *skb)
{
	struct nlmsghdr *nlh = NULL;
	//接收数据
	char *data;
	int pid;
	char msg[2048];
	nlh = nlmsg_hdr(skb);
	if ((nlh->nlmsg_len < NLMSG_HDRLEN) || (skb->len < nlh->nlmsg_len)) {
		printk("Illegal netlink packet!\n");
		return;
	}
	//获取数据
	data = (char *) NLMSG_DATA(nlh);
	//analysis the msg
	int type=data[0]-'0';   //第一个字节为工作类型
	char buf[256];
	int id;
	unsigned int sip;
	char tid;//rule/nat/connection
	printk("recv buf %s type %d\n",data,type);
	memset(msg,0,2048);
	pid = nlh->nlmsg_pid;
	printk("to send back %s\n",msg);
	nltest_ksend(msg, pid);
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


//init
int __init nltest_init(void)
{

    //创建neilink socket
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
	//nat in
	natop_in.hook = (nf_hookfn *)nat_in;  
	natop_in.pf = PF_INET;  
	natop_in.hooknum = NF_INET_LOCAL_IN;  
	natop_in.priority = NF_IP_PRI_FIRST;
	//nat out
	natop_out.hook = (nf_hookfn *)nat_out;  
	natop_out.pf = PF_INET;  
	natop_out.hooknum = NF_INET_LOCAL_IN;  
	natop_out.priority = NF_IP_PRI_FIRST;    
	nf_register_net_hook(&nfho);                                  /// 注册一个钩子函数  
	nf_register_net_hook(&natop_in);
	nf_register_net_hook(&natop_out);
	return 0;
}

//exit
void __exit nltest_exit(void)
{
	sock_release(nlsk->sk_socket);
	printk("kexec myfirewall exit ...\n");  
	nf_unregister_net_hook(&nfho);  
	nf_unregister_net_hook(&natop_in);
	nf_unregister_net_hook(&natop_out);
	printk("Netlink test module exit!\n");
}

module_init(nltest_init);
module_exit(nltest_exit);
MODULE_LICENSE("GPL");
