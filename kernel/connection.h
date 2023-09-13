#ifndef CONNECTION_H
#define CONNECTION_H

#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include <linux/spinlock.h>

#include "nec.h"

#define CONNECTION_BUCKET_CNT 256
#define CONNECTION_BUCKET_BITS 8

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
}icmp_connection;

void* find_con(void*, size_t, unsigned);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
void icmp_timer_callback(struct timer_list*);
void tu_timer_callback(struct timer_list*);
#else
void icmp_timer_callback(unsigned long);
void tu_timer_callback(unsigned long);
#endif
void add_connection(void*, unsigned, bool);
void del_tu_connection(connection*, bool);
void del_icmp_connection(icmp_connection*, bool);

bool compare_icmp_hdr_strict(icmp_header*, icmp_header*);
bool compare_tu_hdr_strict(tu_header*, tu_header*);
void delink_icmp(icmp_connection*, icmp_connection**);
void delink_tu(connection*, connection**);
void inlink_icmp(icmp_connection*, icmp_connection**);
void inlink_tu(connection*, connection**);
void reset_timer(void*, unsigned, unsigned);
unsigned get_next_timeout(unsigned, unsigned);

#endif
