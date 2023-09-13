#ifndef COMMON_H
#define COMMON_H

#include <QFile>
#include <QDebug>
#include <fcntl.h>
#include <QDateTime>
#include <sys/ioctl.h>
#include <QMessageBox>
#include <QStandardItemModel>

#define	HP_PRE_ROUTING		0
#define	HP_LOCAL_IN			1
#define	HP_LOCAL_OUT		2
#define	HP_FORWARD			3
#define	HP_POST_ROUTING		4

#define INFO_CON            0
#define INFO_RULE           1
#define INFO_LOG            2

#define PROTO_TCP           0
#define PROTO_UDP           1
#define PROTO_ICMP          2
#define RULE_TCP            PROTO_TCP
#define RULE_UDP            PROTO_UDP
#define RULE_ICMP           PROTO_ICMP

#define HOOK_CNT 5
#define INFO_CNT 3

#define MAX_RANGE_IN_A_RULE 32

// ioctl commands

#define IOCTL_ALL_PROTO     0
#define IOCTL_TCP           8
#define IOCTL_UDP           0x10
#define IOCTL_ICMP          0x18
#define IOCTL_PROTO(x)      (x << 3)

#define IOCTL_SET_DEFAULT   0x80
#define IOCTL_GET_DEFAULT   0x80
#define IOCTL_GET_RULE      0x20
#define IOCTL_DEL_RULE      0x40

#define IOCTL_SET_CONFIG    0x2F
#define IOCTL_SET_RULE_PATH 0x3D
#define IOCTL_GET_RULE_PATH 0x3E
#define IOCTL_ADD_RULE      0x3F
#define IOCTL_GET_CON       0x78
#define IOCTL_WRITE_CON     0x79
#define IOCTL_CLEAR_LOG     0x7A
#define IOCTL_GET_LOG       0x7B
#define IOCTL_WRITE_LOG     0x7C
#define IOCTL_GET_NEW_LOG   0x7D
#define IOCTL_GET_CONFIG    0x7E

#define DEFAULT_ACTION      0
#define DEFAULT_LOG         1
#define DEFAULT_OPTIONS     2

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
    ((proto == RULE_TCP) ? sizeof(tcp_log) * log_length[RULE_TCP] : \
    (proto == RULE_UDP) ? sizeof(udp_log) * log_length[RULE_UDP] : \
    sizeof(icmp_log) * log_length[RULE_ICMP]))
#define MAX_RULE_BUFLEN (sizeof(rule_ifh) + sizeof(fwrule_user) * max_rule)
#define RULEOUT_SIZE(x) (((rule_ifh*)x)->rule_num * sizeof(fwrule_user) + sizeof(rule_ifh))

#define SPACE(str) (QString("   ") + (str) + "   ")

#define HOOK_CNT 5
#define PROTOCOL_SUPPORTED 3

typedef struct CIDR{
    unsigned int ip;
    unsigned char mask;
}CIDR;

typedef struct port_range{
    unsigned short start;
    unsigned short end;
}port_range;

typedef struct ipport{
    unsigned int ip;
    unsigned short port;
}ipport;

typedef struct NAT_static_config{
    unsigned int lan_ip;
    unsigned int wan_ip;
}NAT_static_config;

typedef struct NAT_dynamic_config{
    CIDR lan_ippool;
    CIDR wan_ippool;
}NAT_dynamic_config;

typedef struct NAT_PAT_config{
    ipport lan;
    ipport wan;
}NAT_PAT_config;

typedef struct NAT_config{
    unsigned char NAT_mode;
    union{
        NAT_static_config sc;
        NAT_dynamic_config dc;
        NAT_PAT_config pc;
    }config;
}NAT_config;

typedef struct lhy_firewall_rule_user{
    CIDR src_ip;
    CIDR dst_ip;
    // there may be multiple ports
    port_range src_ports[MAX_RANGE_IN_A_RULE];
    port_range dst_ports[MAX_RANGE_IN_A_RULE];
    // use the lowest 3 bits. from low to high: tcp, udp, icmp
    unsigned int protocol;
    unsigned int src_port_len;
    unsigned int dst_port_len;
    unsigned action;	// 0 for reject, 1 for accept
    // NAT content
    unsigned char NAT_mode;
    NAT_config nat_config;
    unsigned timeout;       // duration from user, timestamp to user, 0 for no expiration
    unsigned hook;
}fwrule_user;

typedef struct rule_to_be_inserted{
    fwrule_user rule;
    unsigned insert_pos;
}rule_tbi;

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

typedef struct icmp_header{
    unsigned int cliip;
    unsigned int srvip;
}icmp_header;

typedef struct tu_header{
    unsigned int cliip;     // alias for srcip
    unsigned int srvip;     // alias for dstip
    unsigned short cliport; // alias for srcport
    unsigned short srvport; // alias for dstport
}tu_header;

typedef struct icmp_con_touser{
    icmp_header header;
    unsigned char type;
    size_t last;
    unsigned timeout;
}icmp_con_touser;

typedef struct tcpudp_con_touser{
    tu_header header;
    size_t last;
    unsigned timeout;
}tu_con_touser;

typedef struct icmp_log{
    unsigned long long timestamp;   // 0x00
    unsigned srcip;                 // 0x08
    unsigned dstip;                 // 0x0C
    unsigned char proto;            // 0x10
    unsigned char action;           // 0x11
    unsigned char type;             // 0x12
    unsigned char code;             // 0x13
    unsigned length;
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
    unsigned length;
}udp_log;

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

extern QStandardItemModel* connection_models[PROTOCOL_SUPPORTED];
extern QStandardItemModel* rule_models[HOOK_CNT][PROTOCOL_SUPPORTED];
extern QStandardItemModel* log_models[PROTOCOL_SUPPORTED];
extern int devfd;
extern int frontend_update_interval;

// configs
#define CONFIG_CNT 17
extern unsigned TCP_syn_timeout;                                    // config code = 0
extern unsigned TCP_fin_timeout;                                    // 1
extern unsigned initial_timeout[PROTOCOL_SUPPORTED];                // 2-4
extern unsigned connection_max_timeout[PROTOCOL_SUPPORTED];         // 5-7
extern unsigned TCP_con_timeout_fixed;                              // 8
extern unsigned UDP_con_timeout_fixed;                              // 9
extern unsigned max_con[PROTOCOL_SUPPORTED];                        // 10-12
extern unsigned log_length[PROTOCOL_SUPPORTED];                     // 13-15
extern unsigned max_rule;                                           // 16
extern unsigned default_strategy[HOOK_CNT][PROTOCOL_SUPPORTED];

#define SET_DEFAULT(hook, proto, bit, x) \
    ((default_strategy[hook][proto] & (0x7F ^ (1 << bit))) | (x << bit))

#define CONF_TCP_SYN_TMO    0
#define CONF_TCP_FIN_TMO    1
#define CONF_TCP_INI_TMO    2
#define CONF_UDP_INI_TMO    3
#define CONF_ICMP_INI_TMO   4
#define CONF_TCP_MAX_TMO    5
#define CONF_UDP_MAX_TMO    6
#define CONF_ICMP_MAX_TMO   7
#define CONF_TCP_FIX_TMO    8
#define CONF_UDP_FIX_TMO    9
#define CONF_TCP_MAX_CON    10
#define CONF_UDP_MAX_CON    11
#define CONF_ICMP_MAX_CON   12
#define CONF_TCP_MAX_LOG    13
#define CONF_UDP_MAX_LOG    14
#define CONF_ICMP_MAX_LOG   15
#define CONF_MAX_RULE       16

extern unsigned* configs[CONFIG_CNT];
extern char rule_path[256];
extern const QString hook_names[HOOK_CNT];
extern const QString proto_names[PROTOCOL_SUPPORTED];

// debug functions
void print_binary(char*, int);
bool set_default_strategy(unsigned hook, unsigned proto, unsigned bit, bool val);
QString usectime_tostring(unsigned long long time);
QString sectime_tostring(unsigned long long time);
#endif // COMMON_H
