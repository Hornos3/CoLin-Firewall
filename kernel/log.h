#ifndef LOG_H
#define LOG_H

#include <linux/time.h>
#include <linux/types.h>
#include <linux/spinlock.h>

#include "nec.h"

#define REJECT 0
#define ACCEPT 1

typedef struct icmp_log{
    unsigned long long timestamp;   // 0x00
    unsigned srcip;                 // 0x08
    unsigned dstip;                 // 0x0C
    unsigned char proto;            // 0x10
    unsigned char action;           // 0x11
    unsigned char type;             // 0x12
    unsigned char code;             // 0x13
    unsigned length;                // 0x14
}icmp_log;

typedef struct tcp_log{
    unsigned long long timestamp;   // 0x00
    unsigned srcip;                 // 0x08
    unsigned dstip;                 // 0x0C
    unsigned char proto;            // 0x10
    unsigned char action;           // 0x11
    unsigned short sport;           // 0x12
    unsigned short dport;           // 0x14
    unsigned seq;                   // 0x18
    unsigned ack_seq;               // 0x1C
    unsigned char fin:1,            // 0x20
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
    unsigned long long timestamp;   // 0x00
    unsigned srcip;                 // 0x08
    unsigned dstip;                 // 0x0C
    unsigned char proto;            // 0x10
    unsigned char action;           // 0x11
    unsigned short sport;           // 0x12
    unsigned short dport;           // 0x14
    unsigned length;                // 0x16
}udp_log;

void new_icmp_log(icmp_pkt*, unsigned char);
void new_tcp_log(tcp_pkt*, unsigned char);
void new_udp_log(udp_pkt*, unsigned char);
void clear_log(unsigned);

#endif
