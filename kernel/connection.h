#ifndef CONNECTION_H
#define CONNECTION_H

#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "nec.h"

#define CONNECTION_BUCKET_CNT 256
#define CONNECTION_BUCKET_BITS 8
#define NAT_BUCKET_CNT 256
#define NAT_BUCKET_BITS 8

typedef struct nat_connection{
    ipport lan;
    ipport gate;
    ipport wan;
    struct TCPUDP_connection* con;
    struct nat_connection* prev;
    struct nat_connection* next;
}pat_connection;

typedef struct TCPUDP_connection{
    unsigned char proto;    // RULE_TCP or RULE_UDP
	tu_header header;
	struct timer_list timer;
	size_t hash;
	struct TCPUDP_connection* prev;
	struct TCPUDP_connection* next;
    size_t last;    // the time of the last packet sniffed
    size_t timeout;
    bool log;       // record logs or not
    pat_connection* nat;
    bool is_nat_con;    // If NAT needed, a fake connection will be created for quicker search
    // eg. lan 192.168.100.0/24, wan 102.168.101.2, gateway 192.168.101.1, request from 192.168.100.2
    // We will create two connections: 192.168.100.2 -> 192.168.101.2 and 192.168.101.2 -> 192.168.101.1 (port ...)
    // the latter one is called fake connection.
    struct TCPUDP_connection* con_ptr;    // if is_nat_con, it points to the real connection, else the fake connection
    unsigned next_seq;
    unsigned next_ackseq;
    unsigned status;
}tcp_connection, udp_connection, connection;

typedef struct ICMP_connection{
    unsigned char proto;    // ONLY BE RULE_ICMP
	icmp_header header;
	struct timer_list timer;
	unsigned char type;
	size_t hash;
	struct ICMP_connection* prev;
	struct ICMP_connection* next;
    size_t last;
    size_t timeout;
    bool log;
    // this module does not support NAT for ICMP packets
}icmp_connection;

void* find_con(void*, size_t, unsigned);
void icmp_timer_callback(struct timer_list*);
void tu_timer_callback(struct timer_list*);
void* add_connection(void*, unsigned, bool);
void del_tu_connection(connection*, bool);
void del_icmp_connection(icmp_connection*, bool);
connection* add_fake_connection(connection*);
bool check_and_update_status(connection*, tcp_pkt*);

bool compare_icmp_hdr_strict(icmp_header*, icmp_header*);
bool compare_tu_hdr_strict(tu_header*, tu_header*);
void delink_icmp(icmp_connection*, icmp_connection**);
void delink_tu(connection*, connection**);
void inlink_icmp(icmp_connection*, icmp_connection**);
void inlink_tu(connection*, connection**);
void reset_timer(void*, unsigned, unsigned);
unsigned get_next_timeout(unsigned, unsigned);

unsigned int do_nat_in(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);
unsigned int do_nat_out(void* priv, struct sk_buff* skb, const struct nf_hook_state* state);

#endif
