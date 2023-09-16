#ifndef RULE_H
#define RULE_H

#include "nec.h"

typedef struct lhy_firewall_rule_user{
    CIDR src_ip;
    CIDR dst_ip;
    // there may be multiple ports
    port_range src_ports[MAX_RANGE_IN_A_RULE];
    // in convenience of setting big port ranges for rules
    port_range dst_ports[MAX_RANGE_IN_A_RULE];
    // use the lowest 3 bits. from low to high: tcp, udp, icmp
    unsigned int protocol;
    unsigned int src_port_len;
    unsigned int dst_port_len;
    unsigned action;	// 0 for reject, 1 for accept
    unsigned timeout;       // duration from user, timestamp to user, 0 for no expiration
    unsigned hook;
}fwrule_user;

// Firewall Rule Struct
typedef struct lhy_firewall_rule{
	CIDR src_ip;
	CIDR dst_ip;
	// there may be multiple ports
	port_range src_ports[MAX_RANGE_IN_A_RULE];
	// in convenience of setting big port ranges for rules
	port_range dst_ports[MAX_RANGE_IN_A_RULE];
	unsigned protocol;
	unsigned src_port_len;
	unsigned dst_port_len;
    unsigned action;	// 0 for reject, 1 for accept
    unsigned timeout;
    unsigned hook;

    struct timer_list timer;
	// for constructing lists
	struct lhy_firewall_rule* next;
	struct lhy_firewall_rule* prev;
}fwrule;

//used in add_rule
typedef struct rule_to_be_inserted{
    fwrule_user rule;
    unsigned insert_pos;
}rule_tbi;

//used in del_rule
typedef struct rule_to_be_deleted{
    unsigned proto;
    unsigned hp;
    unsigned pos;
}rule_tbd;

typedef struct rule_infile_head{
    unsigned hook;
    unsigned proto;
    unsigned rule_num;
}rule_ifh;

unsigned match_a_rule(void*, fwrule*, unsigned);
unsigned match_rules(void*, unsigned, unsigned);
bool add_rule(rule_tbi*);
bool del_rule(rule_tbd*);
bool del_all_rule(unsigned, unsigned);
void rule_timer_callback(struct timer_list* t);
bool add_nat(nat_config*);
bool del_nat(nat_config*);

void del_all_timer(void);

#endif
