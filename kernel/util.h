#ifndef UTIL_H
#define UTIL_H

#include "rule.h"
#include "mem_chardev.h"

size_t con_hash(void*, bool);
size_t tcp_hash(struct iphdr*, struct tcphdr*);
size_t udp_hash(struct iphdr*, struct udphdr*);
size_t icmp_hash(struct iphdr*);
size_t tu_hash_header(tu_header*);
size_t icmp_hash_header(icmp_header*);
bool md5_hash(char*, char*, size_t);

icmp_header* swap_peer_icmp(icmp_header*);
tu_header* swap_peer_tu(tu_header*);

bool compare_icmp_hdr_strict(icmp_header*, icmp_header*);
bool compare_tu_hdr_strict(tu_header*, tu_header*);

void delink_icmp(icmp_connection*, icmp_connection**);
void delink_tu(connection*, connection**);
void inlink_icmp(icmp_connection*, icmp_connection**);
void inlink_tu(connection*, connection**);
void delink_rule(fwrule*);
void inlink_rule(fwrule*, unsigned, unsigned, unsigned);
void inlinkend_rule(fwrule*, unsigned, unsigned);
fwrule* rule_indexer(unsigned, unsigned, unsigned);
bool save_all_rules(const char*);
bool load_all_rules(const char*);
void del_all_rules(void);
rule_ifh* get_rule_for_output(unsigned, unsigned);

bool is_inCIDR(unsigned int, CIDR*);
bool is_inrange(unsigned short, port_range*, unsigned int);

tu_header* get_tcp_header(struct iphdr*, struct tcphdr*);
tu_header* get_udp_header(struct iphdr*, struct udphdr*);
icmp_header* get_icmp_header(struct iphdr*);

unsigned long long this_moment_usec(void);

unsigned extract_connections(void*, unsigned, unsigned);
char* get_string_from_user(char*);
unsigned extract_logs(void*, unsigned, unsigned);
unsigned extract_new_logs(void*, unsigned, unsigned);

char* ip_ntoa(unsigned);
char* range_tostring(port_range*, unsigned);
void print_binary(char*, int);
void tcp_bucket_status(void);
void udp_bucket_status(void);
void icmp_bucket_status(void);
unsigned count_tu_bucket(connection*);
unsigned count_icmp_bucket(icmp_connection*);

# endif