// This file is used for user elf programmer.
// Structs below may be useful for interacting with lhy's firewall.
// Firewall Rule Struct
#ifdef KERNEL_STRUCT

#define HOOK_CNT 5
#define PROTOCOL_SUPPORTED 3

typedef struct lhy_firewall_rule{
	CIDR src_ip;
	CIDR dst_ip;
	// there may be multiple ports
	port_range src_ports;
	// in convenience of setting big port ranges for rules
	port_range dst_ports;
	// use the lowest 3 bits. from low to high: tcp, udp, icmp
	unsigned int protocols;			
	unsigned int src_port_len;
	unsigned int dst_port_len;
	struct timer_list timer;
	bool action;	// 0 for reject, 1 for accept
	// NAT content
	unsigned char NAT_mode;
	NAT_config nat_config;
	// for constructing lists
	struct lhy_firewall_rule* next[PROTOCOL_SUPPORTED];
	struct lhy_firewall_rule* prev[PROTOCOL_SUPPORTED];
}fwrule;

typedef struct rule_to_be_inserted{
    fwrule rule;
    unsigned int insert_pos[PROTOCOL_SUPPORTED];
}rule_tbi;

typedef struct icmp_con_touser{
	icmp_header header;
	unsigned char type;
}icmp_con_touser;

typedef struct tcpudp_con_touser{
    tu_header header;
	int status;
}tu_con_touser;

typedef struct con_touser{
    int tu_con_count;
    int icmp_con_count;
    tu_con_touser* tu_cons;
    icmp_con_touser* icmp_cons;
    // then is the connection data from kernel
}con_touser;

#endif
