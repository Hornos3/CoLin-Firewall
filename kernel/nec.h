#ifndef NEC_H
#define NEC_H

#define DEBUG_MODE  // for debug

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/file.h>
#include <linux/icmp.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/inetdevice.h>

#define WORD_SIZE 64

#define KERNEL_STRUCT   // avoid redefinition with public_nec.h

#define CDEV_MAJOR	200
#define CDEV_NAME	"lhy_memcdev"


// NAT_mode
#define NAT_NONE        0
#define NAT_STATIC 		1
#define NAT_DYNAMIC 	2
#define NAT_PAT     	3

// hook points
#define	HP_PRE_ROUTING		0
#define	HP_POST_ROUTING		1

typedef struct CIDR{
	unsigned int ip;
	unsigned char mask;
}CIDR;

typedef struct ipport{
	unsigned int ip;
	unsigned short port;
}ipport;

typedef struct port_range{
    unsigned short start;
    unsigned short end;
}port_range;

typedef struct NAT_static_config{   // NOT SUPPORTED
	unsigned int lan_ip;
	unsigned int wan_ip;
}NAT_static_config;

typedef struct NAT_dynamic_config{  // NOT SUPPORTED
	CIDR lan_ippool;
	CIDR wan_ippool;
}NAT_dynamic_config;

typedef struct NAT_PAT_config{
	CIDR lan;
    unsigned wan;       // outer address of gateway
}NAT_PAT_config;

typedef struct NAT_config{
	unsigned char NAT_mode;
	union{
		NAT_static_config sc;
		NAT_dynamic_config dc;
		NAT_PAT_config pc;
	}config;
    struct NAT_config* prev;
    struct NAT_config* next;
}nat_config;

typedef struct NAT_config_touser{
    unsigned char NAT_mode;
    union{
        NAT_static_config sc;
        NAT_dynamic_config dc;
        NAT_PAT_config pc;
    }config;
}nat_config_touser;

#define HOOK_CNT 2
#define PROTOCOL_SUPPORTED 3
#define DEFAULT_OPTIONS 2

#define RULE_TCP 0
#define RULE_UDP 1
#define RULE_ICMP 2
#define RULE_ALL 3

#define MAX_RANGE_IN_A_RULE 32

// for functons handling connection.
#define TCPUDP		0
#define ICMP		1
#define TCP         2
#define UDP         3

#define TCP_CON_UNDEFINED   0
#define TCP_CON_SYN 		1
#define TCP_CON_SYNACK 		2
#define TCP_CON_ACK			3
#define TCP_CON_CONNECTED	3
#define TCP_CON_FIN_1		4
#define TCP_CON_ACK_1		5
#define TCP_CON_FIN_2		6
#define TCP_CON_ACK_2		7
#define TCP_CON_CLOSED		7

#define TUH_CLIIP header.cliip
#define TUH_SRVIP header.srvip
#define TUH_CLIPORT header.cliport
#define TUH_SRVPORT header.srvport

typedef struct tu_header{
	unsigned int cliip;     // alias for srcip
	unsigned int srvip;     // alias for dstip
	unsigned short cliport; // alias for srcport
	unsigned short srvport; // alias for dstport
}tu_header;

#define I_CLIIP header.cliip;
#define I_SRVIP header.srvip;

typedef struct icmp_header{
	unsigned int cliip;
	unsigned int srvip;
}icmp_header;

// Packet info
typedef struct tcp_packet{
    struct tcphdr* header;
    tu_header* myhdr;
    unsigned length;    // total length, including payload and TCP header
    size_t hash;
}tcp_pkt;

typedef struct udp_packet{
    struct udphdr* header;
    tu_header* myhdr;
    unsigned length;
    size_t hash;
}udp_pkt;

typedef struct icmp_packet{
    struct icmphdr* header;
    icmp_header* myhdr;
    unsigned length;
    size_t hash;
}icmp_pkt;

#endif
