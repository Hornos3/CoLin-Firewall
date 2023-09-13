#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/time.h>
#include <linux/inet.h>
#include <linux/icmp.h>
#include <linux/hash.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/minmax.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <crypto/hash.h>

#include "util.h"
#include "statics.h"

/******************** hash functions ********************/
size_t con_hash(void* con, bool is_icmp){
	if(is_icmp)
		return icmp_hash_header(&((icmp_connection*)con)->header);
	else
		return tu_hash_header(&((connection*)con)->header);
}

size_t tcp_hash(struct iphdr* ip, struct tcphdr* tcp){
    tu_header* tmp = get_tcp_header(ip, tcp);
    unsigned ret = tu_hash_header(tmp);
    kfree(tmp);
    return ret;
}

size_t udp_hash(struct iphdr* ip, struct udphdr* udp){
    tu_header* tmp = get_udp_header(ip, udp);
    unsigned ret = tu_hash_header(tmp);
    kfree(tmp);
    return ret;
}

size_t icmp_hash(struct iphdr* ip){
    icmp_header* icmp = get_icmp_header(ip);
    unsigned ret = icmp_hash_header(icmp);
    kfree(icmp);
    return ret;
}

size_t icmp_hash_header(icmp_header* icmp){
	icmp_header* swap = swap_peer_icmp(icmp);
	char hash[16] = {0};
	md5_hash(hash, (char*)swap, sizeof(icmp_header));
	size_t swap_hashval = *(size_t*)hash;
	md5_hash(hash, (char*)icmp, sizeof(icmp_header));
	size_t hashval = *(size_t*)hash;
	kfree(swap);
	return swap_hashval ^ hashval;
}

size_t tu_hash_header(tu_header* tu){
	tu_header* swap = swap_peer_tu(tu);
	char hash[16] = {0};
	md5_hash(hash, (char*)swap, sizeof(tu_header));
	size_t swap_hashval = *(size_t*)hash;
	md5_hash(hash, (char*)tu, sizeof(tu_header));
	size_t hashval = *(size_t*)hash;
	kfree(swap);
	return swap_hashval ^ hashval;
}


bool md5_hash(char *result, char* data, size_t len){
    size_t size = 0;
    struct shash_desc *desc;
    struct crypto_shash **shash = NULL;
 
    shash = kmalloc(sizeof(struct crypto_shash*), GFP_KERNEL);
    if(NULL == shash)
    {
         return false;
    }
    *shash = crypto_alloc_shash("md5", 0, CRYPTO_ALG_ASYNC);
    size = sizeof(struct shash_desc) + crypto_shash_descsize(*shash);
    desc = kmalloc(size, GFP_KERNEL);
    if(desc == NULL)
    {
        return false;
    }
    desc->tfm = *shash;
 
    crypto_shash_init(desc);
    crypto_shash_update(desc, data, len);
    crypto_shash_final(desc, result);
    crypto_free_shash(desc->tfm);
 
    kfree(shash);
    kfree(desc);
    return true;
}

/******************** swap functions ********************/

// swap the client and server of a connection, used for calculating hash
icmp_header* swap_peer_icmp(icmp_header* hdr){
	icmp_header* swap = (icmp_header*)kmalloc(sizeof(icmp_header), GFP_KERNEL);
	swap->cliip = hdr->srvip;
	swap->srvip = hdr->cliip;
	return swap;
}

tu_header* swap_peer_tu(tu_header* hdr){
	tu_header* swap = (tu_header*)kmalloc(sizeof(tu_header), GFP_KERNEL);
	swap->cliip = hdr->srvip;
	swap->cliport = hdr->srvport;
	swap->srvip = hdr->cliip;
	swap->srvport = hdr->cliport;
	return swap;
}

/******************** compare functions ********************/
bool compare_icmp_hdr_strict(icmp_header* first, icmp_header* second){
    if(!memcmp(first, second, sizeof(icmp_header)))
        return true;
    return (first->cliip == second->srvip && first->srvip == second->cliip);
}

bool compare_tu_hdr_strict(tu_header* first, tu_header* second){
    if(!memcmp(first, second, sizeof(tu_header)))
        return true;
    return first->cliip == second->srvip && first->srvip == second->cliip &&
           first->cliport == second->srvport && 
           first->srvport == second->cliport;
}

/******************** linked list functions ********************/
void delink_icmp(icmp_connection* con, icmp_connection** bucket){
    if(con == *bucket){
        *bucket = con->next;
        if(con->next != NULL)
            con->next->prev = NULL;
        return;
    }
    if(con->prev == NULL){
        char* srcip = ip_ntoa(con->header.cliip);
        char* dstip = ip_ntoa(con->header.srvip);
        printk("Error while deleted a tu connection: src ip = %s, dst ip = %s\n", srcip, dstip);
        kfree(srcip);
        kfree(dstip);
        return;
    }
    con->prev->next = con->next;
    if(con->next != NULL)
        con->next->prev = con->prev;
}

void delink_tu(connection* con, connection** bucket){
    if(con == *bucket){
        *bucket = con->next;
        if(con->next != NULL)
            con->next->prev = NULL;
        return;
    }
    if(con->prev == NULL){
        char* srcip = ip_ntoa(con->header.cliip);
        char* dstip = ip_ntoa(con->header.srvip);
        printk("Error while deleted a tu connection: src ip = %s, dst ip = %s, src port = %d, dst port = %d\n",
               srcip, dstip, con->header.cliport, con->header.srvport);
        kfree(srcip);
        kfree(dstip);
        return;
    }
    con->prev->next = con->next;
    if(con->next != NULL)
        con->next->prev = con->prev;
}

void inlink_icmp(icmp_connection* con, icmp_connection** bucket){
    con->prev = NULL;
    con->next = *bucket;
    if(*bucket)
        (*bucket)->prev = con;
    *bucket = con;
}

void inlink_tu(connection* con, connection** bucket){
    con->prev = NULL;
    con->next = *bucket;
    if(*bucket)
        (*bucket)->prev = con;
    *bucket = con;
}

void inlink_rule(fwrule* new_rule, unsigned pos, unsigned hp, unsigned protocol){
    if(hp >= HOOK_CNT || protocol >= PROTOCOL_SUPPORTED)
        return;
    fwrule* il = rule_indexer(hp, protocol, pos);
    if(il == NULL) {
        inlinkend_rule(new_rule, hp, protocol);
        return;
    }
    if(il->prev == NULL){
        new_rule->prev = NULL;
        new_rule->next = rules[hp][protocol];
        rules[hp][protocol]->prev = new_rule;
        rules[hp][protocol] = new_rule;
        return;
    }
    new_rule->prev = il->prev;
    new_rule->next = il;
    il->prev->next = new_rule;
    il->prev = new_rule;
}

void inlinkend_rule(fwrule* new_rule, unsigned hp, unsigned protocol){
    if(hp >= HOOK_CNT || protocol >= PROTOCOL_SUPPORTED)
        return;
    if(rules[hp][protocol] == NULL){
        rules[hp][protocol] = new_rule;
        rules_end[hp][protocol] = new_rule;
        new_rule->prev = new_rule->next = NULL;
        return;
    }
    rules_end[hp][protocol]->next = new_rule;
    new_rule->prev = rules_end[hp][protocol];
    new_rule->next = NULL;
}

void delink_rule(fwrule* new_rule){
    if(new_rule->hook >= HOOK_CNT || new_rule->protocol >= PROTOCOL_SUPPORTED)
        return;
    // must be locked before called this
    if(new_rule->prev == NULL){      // first place
        rules[new_rule->hook][new_rule->protocol] = new_rule->next;
        if(rules[new_rule->hook][new_rule->protocol] != NULL)
            rules[new_rule->hook][new_rule->protocol]->prev = NULL;
    }else{
        new_rule->prev->next = new_rule->next;
        if(new_rule->next != NULL)
            new_rule->next->prev = new_rule->prev;
        else    // last place
            rules_end[new_rule->hook][new_rule->protocol] = new_rule->prev;
    }
    rule_cnt[new_rule->hook][new_rule->protocol]--;
    kfree(new_rule);
}

// This function starts the index by 1, not 0
fwrule* rule_indexer(unsigned hp, unsigned proto, unsigned index){
    if(hp >= HOOK_CNT || proto >= PROTOCOL_SUPPORTED)
        return NULL;
    int count = 1;
    fwrule* ptr = rules[hp][proto];
    while(count < index && ptr != NULL){
        ptr = ptr->next;
        index++;
    }
    return ptr;
}

/******************** range functions ********************/

bool is_inCIDR(unsigned int ip, CIDR* cidr){
    if(cidr->mask == 0)
        return true;
    return !((ip ^ cidr->ip) & (0xFFFFFFFF << (32 - cidr->mask)));
}

// used for ports
// this function DO NOT check whether the ranges are legal.
bool is_inrange(unsigned short port, port_range* ranges, unsigned int rlen){
    int i = 0;
    for(; i<rlen; i++)
        if(port >= ranges[i].start && port <= ranges[i].end)
            return true;
    return false;
}

/******************** header functions ********************/

tu_header* get_tcp_header(struct iphdr* ip, struct tcphdr* tcp){
    tu_header* ret = (tu_header*)kmalloc(sizeof(tu_header), GFP_KERNEL);
    ret->cliip = ntohl(ip->saddr);
    ret->srvip = ntohl(ip->daddr);
    ret->cliport = ntohs(tcp->source);
    ret->srvport = ntohs(tcp->dest);
    return ret;
}

tu_header* get_udp_header(struct iphdr* ip, struct udphdr* udp){
    tu_header* ret = (tu_header*)kmalloc(sizeof(tu_header), GFP_KERNEL);
    ret->cliip = ntohl(ip->saddr);
    ret->srvip = ntohl(ip->daddr);
    ret->cliport = ntohs(udp->source);
    ret->srvport = ntohs(udp->dest);
    return ret;
}

icmp_header* get_icmp_header(struct iphdr* ip){
    icmp_header* ret = (icmp_header*)kmalloc(sizeof(icmp_header), GFP_KERNEL);
    ret->cliip = ntohl(ip->saddr);
    ret->srvip = ntohl(ip->daddr);
    return ret;
}

/******************** time functions ********************/
unsigned long long this_moment_usec(){
    return ktime_get_real_ns() / 1000;
}

/******************** user program functions ********************/
// buf: tu_con_touser* or icmp_con_touser*, an array
unsigned extract_connections(void* buf, unsigned proto, unsigned limit){
    if(proto >= RULE_ALL)
        return -1;
    unsigned idx = 0;
    for(int bucket = 0; bucket < CONNECTION_BUCKET_CNT; bucket++){
        void* ptr = con_bucket[proto][bucket];
        while(ptr && idx < limit){
            if(proto == RULE_TCP || proto == RULE_UDP){
                ((tu_con_touser*)buf)[idx].timeout = ((connection*)ptr)->timeout + ((connection*)ptr)->last / 1000000;
                ((tu_con_touser*)buf)[idx].last = ((connection*)ptr)->last;
                memcpy(&((tu_con_touser*)buf)[idx++].header, &((connection*)ptr)->header,HEADER_SIZE(proto));
                ptr = ((connection*)ptr)->next;
            }
            else{
                memcpy(&((icmp_con_touser*)buf)[idx++].header, &((icmp_connection*)ptr)->header,HEADER_SIZE(proto));
                ((icmp_con_touser*)buf)[idx].timeout = ((icmp_con_touser*)ptr)->timeout + ((icmp_con_touser*)ptr)->last / 1000000;
                ((icmp_con_touser*)buf)[idx].last = ((icmp_con_touser*)ptr)->last;
                ((icmp_con_touser*)buf)->type = ((icmp_con_touser*)ptr)->type;
                ptr = ((icmp_connection*)ptr)->next;
            }
        }
        if(idx == limit)
            return limit;
    }
    return idx;
}

void* lhy_realloc(void* ori, unsigned old_size, unsigned new_size){
    void* new = kmalloc(new_size, GFP_KERNEL);
    memcpy(new, ori, old_size > new_size ? new_size : old_size);
    kfree(ori);
    return new;
}

char* get_string_from_user(char* userbuf){
    unsigned buflen = 0x20;
    char* kernbuf = (char*)kmalloc(buflen, GFP_KERNEL);
    int copied = 0;
    while(true){
        if(copied == buflen){
            kernbuf = (char*)lhy_realloc(kernbuf, buflen, buflen + 0x20);
            buflen += 0x20;
        }
        unsigned long ret = copy_from_user(kernbuf + copied, userbuf + copied, 1);
        if(ret){
            printk(KERN_ERR "Failed to copy from user, %s: line %d\n", __FILE__, __LINE__);
            return NULL;
        }
        if(kernbuf[copied] == '\0')
            return kernbuf;
        ++copied;
    }
    return kernbuf;
}

unsigned extract_logs(void* buf, unsigned proto, unsigned limit){
    if(proto >= RULE_ALL)
        return -1;
    if(log_cnt[proto] == 0)
        return 0;
    if(limit > log_cnt[proto])
        limit = log_cnt[proto];
    unsigned start_point = log_cnt[proto] > next_log_ptr[proto] ?
            next_log_ptr[proto] + log_length[proto] - log_cnt[proto] :
            next_log_ptr[proto] - log_cnt[proto];
    unsigned copy_cnt = limit > log_cnt[proto] ? log_cnt[proto] : limit;
    if(log_length[proto] - start_point >= copy_cnt){
        memcpy(buf, LOG_ARR_OFFSET(logs[proto], proto, start_point),LOG_SIZE(proto) * limit);
        new_log_cnt[proto] -= limit;
        return copy_cnt;
    }
    memcpy(buf, LOG_ARR_OFFSET(logs[proto], proto, start_point),
           LOG_SIZE(proto) * (log_length[proto] - start_point));
    memcpy(LOG_ARR_OFFSET(buf, proto, (log_length[proto] - start_point)), logs[proto],
           LOG_SIZE(proto) * (copy_cnt + start_point - log_length[proto]));
    new_log_cnt[proto] -= limit;
    return copy_cnt;
}

// won't check the rewind
unsigned extract_new_logs(void* buf, unsigned proto, unsigned limit){
    if(proto >= RULE_ALL)
        return -1;
    if(new_log_cnt[proto] == 0)
        return 0;
    if(new_log_cnt[proto] > log_length[proto])
        new_log_cnt[proto] = log_length[proto];
    unsigned start_point = (new_log_cnt[proto] > next_log_ptr[proto]) ?
                           next_log_ptr[proto] + log_length[proto] - new_log_cnt[proto] :
                           next_log_ptr[proto] - new_log_cnt[proto];    // You can get a part of new logs, but no need
    unsigned copy_cnt = limit > new_log_cnt[proto] ? new_log_cnt[proto] : limit;
    if(log_length[proto] - start_point >= copy_cnt){   // memcpy once
        memcpy(buf, LOG_ARR_OFFSET(logs[proto], proto, start_point),LOG_SIZE(proto) * limit);
        new_log_cnt[proto] -= limit;
        return copy_cnt;
    }
    memcpy(buf, LOG_ARR_OFFSET(logs[proto], proto, start_point),
           LOG_SIZE(proto) * (log_length[proto] - start_point));
    memcpy(LOG_ARR_OFFSET(buf, proto, (log_length[proto] - start_point)), logs[proto],
           LOG_SIZE(proto) * (copy_cnt + start_point - log_length[proto]));
    new_log_cnt[proto] -= limit;
    return copy_cnt;
}

/******************** debug functions ********************/
char* ip_ntoa(unsigned ip){
    char* buf = (char*)kmalloc(0x10, GFP_KERNEL);
    buf[15] = '\0';
    int idx = 0;
    for(int i=24; i>=0; i-=8){
        int target = (ip >> i) & 0xFF;
        char tmp[4] = {target / 100 + '0', (target / 10) % 10 + '0',
            target % 10 + '0', '\0'};
        int ptr = 0;
        while(tmp[ptr] == '0')
            ptr++;
        if(ptr == 3)
            buf[idx++] = '0';
        else
            while(ptr < 3)
                buf[idx++] = tmp[ptr++];
        if(i)
            buf[idx++] = '.';
    }
    return buf;
}

char* range_tostring(port_range* range, unsigned length){
    char* buf = (char*)kmalloc(0x100, GFP_KERNEL);
    unsigned ptr = 0;
    for(int i=0; i<length; i++){
        int written = snprintf(&buf[ptr], 0x100, "%d~%d", range[i].start, range[i].end);
        ptr += written;
        if(ptr >= 0x100)
            return buf;
    }
    return buf;
}

void print_binary(char* buf, int length){
    printk("---------------------------------------------------------------------------");
    char output_buffer[80];
    printk("Address info starting in %p:", buf);
    int index = 0;
    memset(output_buffer, '\0', 80);
    memset(output_buffer, ' ', 0x10);
    for(int i=0; i<(length % 16 == 0 ? length / 16 : length / 16 + 1); i++){
        char temp_buffer[0x10];
        memset(temp_buffer, '\0', 0x10);
        snprintf(temp_buffer, 80, "%#5x", index);
        strcpy(output_buffer, temp_buffer);
        output_buffer[5] = ' ';
        output_buffer[6] = '|';
        output_buffer[7] = ' ';
        for(int j=0; j<16; j++){
            if(index+j >= length)
                snprintf(output_buffer+8+3*j, 80, "   ");
            else{
                snprintf(output_buffer+8+3*j, 80, "%02x ", ((int)buf[index+j]) & 0xFF);
                if(buf[index+j] < 0x20 || buf[index+j] >= 0x7F)
                    output_buffer[58+j] = '.';
                else
                    output_buffer[58+j] = buf[index+j];
            }
        }
        output_buffer[55] = ' ';
        output_buffer[56] = '|';
        output_buffer[57] = ' ';
        printk("%s", output_buffer);
        memset(output_buffer+58, '\0', 16);
        index += 16;
    }
    printk("---------------------------------------------------------------------------");
}

void tcp_bucket_status(){
    printk("tcp connection buckets: \n");
    printk("   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f");
    for(int i=0; i<16; i++){
        connection** c = (connection**)&(con_bucket[RULE_TCP][i*16]);
        printk("%1x  %-3d%-3d%-3d%-3d%-3d%-3d%-3d%-3d%-3d%-3d"
        "%-3d%-3d%-3d%-3d%-3d%-3d\n", i,
        count_tu_bucket(c[0]), count_tu_bucket(c[1]), count_tu_bucket(c[2]),
        count_tu_bucket(c[3]), count_tu_bucket(c[4]), count_tu_bucket(c[5]),
        count_tu_bucket(c[6]), count_tu_bucket(c[7]), count_tu_bucket(c[8]),
        count_tu_bucket(c[9]), count_tu_bucket(c[10]), count_tu_bucket(c[11]),
        count_tu_bucket(c[12]), count_tu_bucket(c[13]), count_tu_bucket(c[14]),
        count_tu_bucket(c[15]));
    }
}

void udp_bucket_status(){
    printk("udp connection buckets: \n");
    printk("   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f");
    for(int i=0; i<16; i++){
        connection** c = (connection**)&(con_bucket[RULE_UDP][i*16]);
        printk("%1x  %-3d%-3d%-3d%-3d%-3d%-3d%-3d%-3d%-3d%-3d"
               "%-3d%-3d%-3d%-3d%-3d%-3d\n", i,
               count_tu_bucket(c[0]), count_tu_bucket(c[1]), count_tu_bucket(c[2]),
               count_tu_bucket(c[3]), count_tu_bucket(c[4]), count_tu_bucket(c[5]),
               count_tu_bucket(c[6]), count_tu_bucket(c[7]), count_tu_bucket(c[8]),
               count_tu_bucket(c[9]), count_tu_bucket(c[10]), count_tu_bucket(c[11]),
               count_tu_bucket(c[12]), count_tu_bucket(c[13]), count_tu_bucket(c[14]),
               count_tu_bucket(c[15]));
    }
}

void icmp_bucket_status(){
    printk("icmp connection buckets: \n");
    printk("   0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f");
    for(int i=0; i<16; i++){
        icmp_connection** c = (icmp_connection**)&(con_bucket[RULE_ICMP][i*16]);
        printk("%1x  %-3d%-3d%-3d%-3d%-3d%-3d%-3d%-3d%-3d%-3d"
        "%-3d%-3d%-3d%-3d%-3d%-3d\n", i,
        count_icmp_bucket(c[0]), count_icmp_bucket(c[1]),
        count_icmp_bucket(c[2]), count_icmp_bucket(c[3]), 
        count_icmp_bucket(c[4]), count_icmp_bucket(c[5]),
        count_icmp_bucket(c[6]), count_icmp_bucket(c[7]),
        count_icmp_bucket(c[8]), count_icmp_bucket(c[9]), 
        count_icmp_bucket(c[10]), count_icmp_bucket(c[11]), 
        count_icmp_bucket(c[12]), count_icmp_bucket(c[13]), 
        count_icmp_bucket(c[14]), count_icmp_bucket(c[15]));
    }
}

unsigned count_tu_bucket(connection* head){
    unsigned ret = 0;
    while(head){
        head = head->next;
        ret++;
    }
    return ret;
}

unsigned count_icmp_bucket(icmp_connection* head){
    unsigned ret = 0;
    while(head){
        head = head->next;
        ret++;
    }
    return ret;
}

/******************** rmmod functions ********************/
void del_all_timer(){
    // delete timers of connections
    for(int i=0; i<PROTOCOL_SUPPORTED; i++){
        for(int j=0; j<CONNECTION_BUCKET_CNT; j++){
            if(i == RULE_TCP || i == RULE_UDP){
                connection* ptr = (connection*)con_bucket[i][j];
                while(ptr){
                    del_timer(&ptr->timer);
                    ptr = ptr->next;
                }
            }else{
                icmp_connection* ptr = (icmp_connection*)con_bucket[i][j];
                while(ptr){
                    del_timer(&ptr->timer);
                    ptr = ptr->next;
                }
            }
        }
    }
    for(int i=0; i<HOOK_CNT; i++){
        for(int j=0; j<PROTOCOL_SUPPORTED; j++){
            fwrule* ptr = rules[i][j];
            while(ptr){
                del_timer(&ptr->timer);
                ptr = ptr->next;
            }
        }
    }
}

bool save_all_rules(const char* filename){  // in the file is fwrule_user structs, not fwrule
    // NOT RECOMMENDED while firewall is running, because writing to a file is too slow
    int ret;
    ret = write_file(filename, NULL, 0, true);  // clear the content of rule files
    if(ret){
        printk(KERN_ERR "Failed to clear content of %s", filename);
        return false;
    }
    for(int i=0; i<HOOK_CNT; i++){
        for(int j=0; j<PROTOCOL_SUPPORTED; j++){
            void* data = get_rule_for_output(i, j);
            ret = write_file(filename, data, RULEOUT_SIZE(data), false);
            if(ret){
                printk("Failed to write file for hook %d, proto %d", i, j);
                return false;
            }
        }
    }
    ret = write_file(filename, (char*)default_strategy, sizeof(default_strategy), false);
    if(ret)
        return false;
    return true;
}

bool load_all_rules(const char* filename){  // All existing rules will be deleted before loading!
    // check the file first
    struct file* file = filp_open(filename, O_RDONLY, 0);
    if(IS_ERR(file)){
        printk(KERN_ERR "Failed to open file %s: %ld\n", filename, PTR_ERR(file));
        return false;
    }
    filp_close(file, NULL);
    // then delete rules and load rules
    del_all_rules();
    printk(KERN_INFO "All rules clear.");
    long size = file_size(filename);
    if(size == 0){
        printk(KERN_ERR "Failed to load rule infos from %s, the file is empty", filename);
        return false;
    }else if(size < 0){
        printk(KERN_ERR "Failed to load rule infos from %s, cannot open the file", filename);
        return false;
    }else if(size < sizeof(rule_ifh) * PROTOCOL_SUPPORTED * HOOK_CNT + sizeof(default_strategy)){
        printk(KERN_ERR "Failed to load rule infos from %s, file too small", filename);
        return false;
    }
    void* content = kmalloc(size, GFP_KERNEL);
    read_file(filename, content, size);
    rule_ifh* ifh_ptr = content;
    fwrule_user* rule_ptr = NULL;
    while((size_t)ifh_ptr - (size_t)content < size - sizeof(default_strategy)){
        for(int i=0; i<ifh_ptr->rule_num; i++){
            rule_ptr = (fwrule_user*)((size_t)ifh_ptr + sizeof(rule_ifh) + sizeof(fwrule_user) * i);
            if(this_moment_usec() / 1000000 >= rule_ptr->timeout)       // timeout, this rule is now invalid
                continue;
            fwrule* new_rule = (fwrule*)kmalloc(sizeof(fwrule), GFP_KERNEL);
            memcpy((void*)new_rule, (void*)rule_ptr, sizeof(fwrule_user));
            inlinkend_rule(new_rule, ifh_ptr->hook, ifh_ptr->proto);
        }
        ifh_ptr = (rule_ifh*)((size_t)ifh_ptr + sizeof(rule_ifh) + sizeof(fwrule_user) * ifh_ptr->rule_num);
    }
    memcpy((void*)default_strategy, (void*)ifh_ptr, sizeof(default_strategy));
    kfree(content);
    return true;
}

void del_all_rules(){
    for(int i=0; i<HOOK_CNT; i++){
        for(int j=0; j<PROTOCOL_SUPPORTED; j++){
            fwrule* ptr = rules[i][j];
            if(!ptr)
                continue;
            fwrule* next;
            while(ptr){
                next = ptr->next;
                kfree(ptr);
                ptr = next;
            }
        }
    }
    for(int i=0; i<HOOK_CNT; i++) {
        for (int j = 0; j < PROTOCOL_SUPPORTED; j++) {
            rules[i][j] = NULL;
            rules_end[i][j] = NULL;
        }
    }
}

rule_ifh* get_rule_for_output(unsigned hook, unsigned proto){
    spin_lock(&rule_lock);
    rule_ifh* buf = (rule_ifh*)kmalloc(sizeof(rule_ifh) + sizeof(fwrule_user) * rule_cnt[hook][proto], GFP_KERNEL);
    buf->hook = hook;
    buf->proto = proto;
    buf->rule_num = rule_cnt[hook][proto];
    fwrule_user* ru = (fwrule_user*)((size_t)buf + sizeof(rule_ifh));
    fwrule* ptr = rules[hook][proto];
    while(ptr){
        memcpy((void*)ru, (void*)ptr, sizeof(fwrule_user));
        ptr = ptr->next;
        ru += 1;
    }

    spin_unlock(&rule_lock);
    return buf;
}