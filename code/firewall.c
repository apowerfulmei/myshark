#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>


#define NETLINK_TEST	17
#define MSG_LEN	256
#define TCP_N 6
#define UDP_N 17
#define ICMP_N 1

struct msg_to_kernel {
	struct nlmsghdr hdr;
	char data[MSG_LEN];
};
struct u_packet_info {
	struct nlmsghdr hdr;
	char msg[MSG_LEN];
};

char *strlwr(char *s)
{
	 char *str;
	 str = s;
	 while(*str != '\0')
	 {
	  	if(*str >= 'A' && *str <= 'Z') {
	    	*str += 'a'-'A';
	 }
	 	str++;
	 }
	 return s;
 }
void sendMsg(char * data,char *recv)
{
	int dlen;
	struct sockaddr_nl local;
	struct sockaddr_nl kpeer;
	int skfd, ret, kpeerlen = sizeof(struct sockaddr_nl);
	struct nlmsghdr *message;
	struct u_packet_info info;
	char *retval;

	dlen = strlen(data) + 1;

	skfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_TEST);
	if (skfd < 0) {
		printf("can not create a netlink socket\n");
		return ;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = 0;
	if (bind(skfd, (struct sockaddr *) &local, sizeof(local)) != 0) {
		printf("bind() error\n");
		return ;
	}
	memset(&kpeer, 0, sizeof(kpeer));
	kpeer.nl_family = AF_NETLINK;
	kpeer.nl_pid = 0;
	kpeer.nl_groups = 0;

	message = (struct nlmsghdr *) malloc(sizeof(struct msg_to_kernel));
	if (message == NULL) {
		printf("malloc() error\n");
		return ;
	}

	memset(message, '\0', sizeof(struct nlmsghdr));
	message->nlmsg_len = NLMSG_SPACE(dlen);
	message->nlmsg_flags = 0;
	message->nlmsg_type = 0;
	message->nlmsg_seq = 0;
	message->nlmsg_pid = local.nl_pid;

	retval = memcpy(NLMSG_DATA(message), data, strlen(data));
	ret = sendto(skfd, message, message->nlmsg_len, 0, (struct sockaddr *) &kpeer, sizeof(kpeer));
	if (!ret) {
		perror("sendto:");
		exit(-1);
	}

	ret = recvfrom(skfd, &info, sizeof(struct u_packet_info), 0, (struct sockaddr *) &kpeer, &kpeerlen);
	if (!ret) {
		perror("recvfrom:");
		exit(-1);
	}
	close(skfd);
	strcpy(recv,info.msg);
	return 0;
}

unsigned int inet_addr(char *str)   
{   
    int a,b,c,d;   
	char arr[4];   
    sscanf(str,"%d.%d.%d.%d",&a,&b,&c,&d);   
	arr[0] = d; arr[1] = c; arr[2] = b; arr[3] = a;   
	return *(unsigned int*)arr;   
}

int proto_num(char * str)
{
	char * xstr=strlwr(str);
	if(strcmp(str,"tcp")==0)
		return TCP_N;
	if(strcmp(str,"udp")==0)
		return UDP_N;
	if(strcmp(str,"icmp")==0)
		return ICMP_N;
}
void printHelp(void)
{
	printf("-----------------------------------------------------------------------\n");
	printf("add one rule: -a src smask dst dmask sport dport protocol opr log\n");
	printf("add one nat: -t src \n");
	printf("delete one rule/nat: -d -r/n id \n");
	printf("show the rules/nats/connetion: -s -r/n/c\n");
	printf("clear all the rules: -c\n");
	printf("help: -h\n");
	printf("-----------------------------------------------------------------------\n");
}
int main(int argc, char *argv[])
{


	char data[2048];
	char recv[2048];
	switch(argv[1][1])
	{
		case 'a':
		//add增加新的规则
		//saddr smask daddr dmask sport dport protocol opr log
		if(argc!=11)
		{
			printf("Parameter error\n");
			break;
		}
		sprintf(data,"%d %u %s %u %s %s %s %u %s %s",1,inet_addr(argv[2]),argv[3],inet_addr(argv[4]),argv[5],argv[6],argv[7],proto_num(argv[8]),argv[9],argv[10]);
		printf("input %s\n",data);
		sendMsg(data,recv);
		printf("send over\n");
		printf("recv :%s\n",recv);
		break;
		case 'd':
		if(argc!=4)
		{
			printf("Parameter error\n");
			break;
		}
		sprintf(data,"%d %s %s",2,argv[2],argv[3]);
		sendMsg(data,recv);
		printf("%s\n",recv);
		break;
		case 's':
		if(argc!=3)
		{
			printf("Parameter error\n");
			break;
		}
		sprintf(data,"%d %s",3,argv[2]);
		sendMsg(data,recv);
		printf("%s\n",recv);
		break;
		case 'c':
		sprintf(data,"%d",4);
		sendMsg(data,recv);
		printf("%s\n",recv);
		case 'h':
		printHelp();
		break;
		case 't':
		//添加nat
		if(argc!=3)
		{
			printf("Parameter error\n");
			break;
		}
		sprintf(data,"%d %u",5,inet_addr(argv[2]));
		sendMsg(data,recv);
		printf("%s\n",recv);
		break;

		default:
		printf("cmd not exist, use -h to get help\n");
		break;
	}


	return 0;
}

