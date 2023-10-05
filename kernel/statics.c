#include "connection.h"
#include "log.h"
#include "mem_chardev.h"
#include "nec.h"
#include "rule.h"
#include "util.h"

spinlock_t tcp_handler_lock = {};
spinlock_t udp_handler_lock = {};
spinlock_t icmp_handler_lock = {};

// global configs
unsigned int TCP_syn_timeout = 60;
unsigned int TCP_fin_timeout = 60;
unsigned initial_timeout[PROTOCOL_SUPPORTED] = {120, 60, 60};
unsigned connection_max_timeout[PROTOCOL_SUPPORTED] = {7200, 7200, 120};
unsigned TCP_con_timeout_fixed = true;
unsigned UDP_con_timeout_fixed = true;

// connections
spinlock_t con_lock = {};
void* con_bucket[PROTOCOL_SUPPORTED][CONNECTION_BUCKET_CNT] = {{NULL},};
unsigned con_count[PROTOCOL_SUPPORTED] = {0, 0, 0};
unsigned max_con[PROTOCOL_SUPPORTED] = {1024, 1024, 128};

// logs
unsigned next_log_ptr[PROTOCOL_SUPPORTED] = {0, 0, 0};
unsigned log_length[PROTOCOL_SUPPORTED] = {65536, 65536, 4096};
void* logs[PROTOCOL_SUPPORTED] = {NULL, NULL, NULL};
unsigned log_cnt[PROTOCOL_SUPPORTED] = {0, 0, 0};
bool log_rewind[PROTOCOL_SUPPORTED] = {0, 0, 0};
// these variables can make copy_to_user copy less data every time and improves efficiency.
unsigned new_log_cnt[PROTOCOL_SUPPORTED] = {0, 0, 0};
spinlock_t log_lock = {};

// rules
spinlock_t rule_lock = {};
fwrule* rules[HOOK_CNT][PROTOCOL_SUPPORTED] = {{NULL},};
fwrule* rules_end[HOOK_CNT][PROTOCOL_SUPPORTED] = {{NULL},};
// bit 0: default accept/reject
// bit 1: default log/no log
nat_config* nat_rules = NULL;
spinlock_t nat_lock = {};
unsigned char ports[65536] = {0};   // speed up the searching for available port
unsigned short nat_port_start = 40000;
unsigned short nat_port_end = 65535;
unsigned nat_cnt = 0;
unsigned max_nat = 64;
unsigned default_strategy[HOOK_CNT][PROTOCOL_SUPPORTED] = {{0},};
unsigned rule_cnt[HOOK_CNT][PROTOCOL_SUPPORTED] = {{0}, };
unsigned max_rule = 256;    // maximum length of each rule linked list

// others
char* hp_names[5] = {
    "PRE_ROUTING",
    "LOCAL_IN",
    "LOCAL_OUT",
    "FORWARD",
    "POST_ROUTING"
};

char* proto_names[3] = {
    "TCP", "UDP", "ICMP"
};

char rule_path[256] = "/etc/lhy_firewall/rules";
char* default_rule_path = "/tmp/lhy_firewall/rules";