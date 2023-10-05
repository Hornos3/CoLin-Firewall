#ifndef LOG_H
#define LOG_H

#include <linux/time.h>
#include <linux/types.h>
#include <linux/spinlock.h>

#include "nec.h"

#define REJECT 0
#define ACCEPT 1

typedef struct icmp_log{
    unsigned long long timestamp;
    unsigned srcip;
    unsigned dstip;
    unsigned char proto;
    unsigned char hp;
    unsigned char action;
    unsigned char type;
    unsigned char code;
    unsigned length;
}icmp_log;

typedef struct tcp_log{
    unsigned long long timestamp;
    unsigned srcip;
    unsigned dstip;
    unsigned char proto;
    unsigned char hp;
    unsigned char action;
    unsigned short sport;
    unsigned short dport;
    unsigned seq;
    unsigned ack_seq;
    unsigned char fin:1,
                  syn:1,
                  rst:1,
                  psh:1,
                  ack:1,
                  urg:1,
                  ece:1,
                  cwr:1;
    unsigned length;
}tcp_log;

typedef struct udp_log{
    unsigned long long timestamp;
    unsigned srcip;
    unsigned dstip;
    unsigned char proto;
    unsigned char hp;
    unsigned char action;
    unsigned short sport;
    unsigned short dport;
    unsigned length;
}udp_log;

void new_icmp_log(icmp_pkt*, unsigned char, unsigned char);
void new_tcp_log(tcp_pkt*, unsigned char, unsigned char);
void new_udp_log(udp_pkt*, unsigned char, unsigned char);
void clear_log(unsigned);

#endif
