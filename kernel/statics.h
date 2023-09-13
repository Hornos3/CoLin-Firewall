#include "connection.h"
#include "log.h"
#include "mem_chardev.h"
#include "nec.h"
#include "rule.h"
#include "util.h"

#define TO_USER_SIZE(proto) ((proto == RULE_TCP || proto == RULE_UDP) ? (sizeof(tu_con_touser)) : (sizeof(icmp_con_touser)))
#define HEADER_SIZE(proto) ((proto == RULE_TCP || proto == RULE_UDP) ? (sizeof(tu_header)) : (sizeof(icmp_header)))
#define LOG_SIZE(proto) ((proto == RULE_TCP) ? (sizeof(tcp_log)) : \
                         (proto == RULE_UDP) ? (sizeof(udp_log)) : \
                         sizeof(icmp_log))
#define CON_SIZE(proto) ((proto == RULE_TCP || proto == RULE_UDP) ? (sizeof(connection)) : (sizeof(icmp_connection)))
#define PTR_OFFSET(x, off) ((void*)((size_t)x + off))
#define LOG_ARR_OFFSET(x, proto, off) ( \
            (proto == RULE_TCP) ? PTR_OFFSET(x, sizeof(tcp_log) * (size_t)off) : \
            (proto == RULE_UDP) ? PTR_OFFSET(x, sizeof(udp_log) * (size_t)off) : \
            PTR_OFFSET(x, sizeof(icmp_log) * (size_t)off))

extern spinlock_t tcp_handler_lock;
extern spinlock_t udp_handler_lock;
extern spinlock_t icmp_handler_lock;

// global configs
extern unsigned int TCP_syn_timeout;                                // config code = 0
extern unsigned int TCP_fin_timeout;                                // 1
extern unsigned initial_timeout[PROTOCOL_SUPPORTED];                // 2-4
extern unsigned connection_max_timeout[PROTOCOL_SUPPORTED];         // 5-7
extern unsigned TCP_con_timeout_fixed;                              // 8
extern unsigned UDP_con_timeout_fixed;                              // 9

// connections
extern spinlock_t con_lock;
extern void* con_bucket[PROTOCOL_SUPPORTED][CONNECTION_BUCKET_CNT];

extern unsigned con_count[PROTOCOL_SUPPORTED];
extern unsigned max_con[PROTOCOL_SUPPORTED];                        // 10-12

// logs
extern unsigned next_log_ptr[PROTOCOL_SUPPORTED];
extern unsigned log_length[PROTOCOL_SUPPORTED];                     // 13-15
extern void* logs[PROTOCOL_SUPPORTED];
extern unsigned log_cnt[PROTOCOL_SUPPORTED];
extern bool log_rewind[PROTOCOL_SUPPORTED];
extern spinlock_t log_lock;

extern unsigned new_log_cnt[PROTOCOL_SUPPORTED];

// rules

extern spinlock_t rule_lock;
extern fwrule* rules[HOOK_CNT][PROTOCOL_SUPPORTED];
extern fwrule* rules_end[HOOK_CNT][PROTOCOL_SUPPORTED];
extern unsigned default_strategy[HOOK_CNT][PROTOCOL_SUPPORTED];
extern unsigned rule_cnt[HOOK_CNT][PROTOCOL_SUPPORTED];
extern unsigned max_rule;                                           // 16

// others

extern char* hp_names[5];
extern char* proto_names[3];
extern char rule_path[256];
extern char* default_rule_path;