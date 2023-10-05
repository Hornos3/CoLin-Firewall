#ifndef MEM_CHARDEV_H
#define MEM_CHARDEV_H

#include "log.h"
#include "rule.h"
#include "connection.h"
#include "statics.h"

#ifndef KERNEL_STRUCT
#define KERNEL_STRUCT
#endif

#define MAX_CON_BUFLEN_ALL (sizeof(con_touser) + \
    sizeof(tu_con_touser) * (max_con[RULE_TCP] + max_con[RULE_UDP]) + \
    sizeof(icmp_con_touser) * max_con[RULE_ICMP])
#define MAX_LOG_BUFLEN_ALL (sizeof(log_touser) + \
    sizeof(tcp_log) * log_length[RULE_TCP] + \
    sizeof(udp_log) * log_length[RULE_UDP] + \
    sizeof(icmp_log) * log_length[RULE_ICMP])
#define MAX_CON_BUFLEN(proto) (sizeof(con_touser) + \
    ((proto == RULE_TCP) ? sizeof(tu_con_touser) * max_con[RULE_TCP] : \
    (proto == RULE_UDP) ? sizeof(tu_con_touser) * max_con[RULE_TCP] : \
    sizeof(icmp_con_touser) * max_con[RULE_ICMP]))
#define MAX_LOG_BUFLEN(proto) (sizeof(log_touser) + \
    (proto == RULE_TCP) ? sizeof(tcp_log) * log_length[RULE_TCP] : \
    (proto == RULE_UDP) ? sizeof(udp_log) * log_length[RULE_UDP] : \
    sizeof(icmp_log) * log_length[RULE_ICMP])
#define MAX_RULE_BUFLEN (sizeof(rule_ifh) + sizeof(fwrule_user) * max_rule)
#define MAX_NAT_BUFLEN (sizeof(nat_config_touser) * max_nat)
#define RULEOUT_SIZE(x) (((rule_ifh*)x)->rule_num * sizeof(fwrule_user) + sizeof(rule_ifh))

typedef struct icmp_con_touser{
	icmp_header header;
	unsigned char type;
    size_t last;
    unsigned timeout;
}icmp_con_touser;

typedef struct tcpudp_con_touser{
    tu_header header;
    ipport pat;
    size_t last;
    unsigned timeout;
}tu_con_touser;

typedef struct con_touser{
    size_t total_size;
    unsigned con_count[PROTOCOL_SUPPORTED];
    void* cons[PROTOCOL_SUPPORTED];
}con_touser;

typedef struct log_touser{
    size_t total_size;
    unsigned log_count[PROTOCOL_SUPPORTED];
    void* logs[PROTOCOL_SUPPORTED];
}log_touser;

typedef struct config_user{
    unsigned id;
    unsigned value;
}config_user;

con_touser* get_connections(unsigned long);
log_touser* get_logs(unsigned long);
log_touser* get_new_logs(unsigned long);
int write_file(const char*, const char*, size_t, bool);
int read_file(const char*, char*, size_t);
long long file_size(const char*);

#endif
