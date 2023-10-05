#include "log.h"
#include "util.h"
#include "statics.h"

void new_icmp_log(icmp_pkt* pkt, unsigned char action, unsigned char hp){
    spin_lock(&log_lock);
    icmp_log* target = LOG_ARR_OFFSET(logs[RULE_ICMP], RULE_ICMP, next_log_ptr[RULE_ICMP]);
    target->timestamp = this_moment_usec();
    target->srcip = pkt->myhdr->cliip;
    target->dstip = pkt->myhdr->srvip;
    target->proto = RULE_ICMP;
    target->action = action;
    target->hp = hp;
    target->type = pkt->header->type;
    target->code = pkt->header->code;
    target->length = pkt->length;
    next_log_ptr[RULE_ICMP]++;
    if(!log_rewind[RULE_ICMP])
        log_cnt[RULE_ICMP]++;
    if(next_log_ptr[RULE_ICMP] >= log_length[RULE_ICMP]){
        next_log_ptr[RULE_ICMP] = 0;
        log_rewind[RULE_ICMP] = true;
    }
    if(new_log_cnt[RULE_ICMP] < log_length[RULE_ICMP])
        new_log_cnt[RULE_ICMP]++;
    spin_unlock(&log_lock);
}

void new_tcp_log(tcp_pkt* pkt, unsigned char action, unsigned char hp){
    spin_lock(&log_lock);
    tcp_log* target = LOG_ARR_OFFSET(logs[RULE_TCP], RULE_TCP, next_log_ptr[RULE_TCP]);
    target->timestamp = this_moment_usec();
    target->srcip = pkt->myhdr->cliip;
    target->dstip = pkt->myhdr->srvip;
    target->proto = RULE_TCP;
    target->action = action;
    target->hp = hp;
    target->sport = pkt->myhdr->cliport;
    target->dport = pkt->myhdr->srvport;
    target->seq = ntohl(pkt->header->seq);
    target->ack_seq = ntohl(pkt->header->ack_seq);
    target->fin = pkt->header->fin;
    target->syn = pkt->header->syn;
    target->rst = pkt->header->rst;
    target->psh = pkt->header->psh;
    target->ack = pkt->header->ack;
    target->urg = pkt->header->urg;
    target->ece = pkt->header->ece;
    target->cwr = pkt->header->cwr;
    target->length = pkt->length;
    next_log_ptr[RULE_TCP]++;
    if(!log_rewind[RULE_TCP])
        log_cnt[RULE_TCP]++;
    if(next_log_ptr[RULE_TCP] >= log_length[RULE_TCP]){
        next_log_ptr[RULE_TCP] = 0;
        log_rewind[RULE_TCP] = true;
    }
    if(new_log_cnt[RULE_TCP] < log_length[RULE_TCP])
        new_log_cnt[RULE_TCP]++;
    spin_unlock(&log_lock);

}

void new_udp_log(udp_pkt* pkt, unsigned char action, unsigned char hp){
    spin_lock(&log_lock);
    udp_log* target = LOG_ARR_OFFSET(logs[RULE_UDP], RULE_UDP, next_log_ptr[RULE_UDP]);
    target->timestamp = this_moment_usec();
    target->srcip = pkt->myhdr->cliip;
    target->dstip = pkt->myhdr->srvip;
    target->proto = RULE_UDP;
    target->action = action;
    target->hp = hp;
    target->sport = pkt->myhdr->cliport;
    target->dport = pkt->myhdr->srvport;
    target->length = pkt->length;
    next_log_ptr[RULE_UDP]++;
    if(!log_rewind[RULE_UDP])
        log_cnt[RULE_UDP]++;
    if(next_log_ptr[RULE_UDP] >= log_length[RULE_UDP]){
        next_log_ptr[RULE_UDP] = 0;
        log_rewind[RULE_UDP] = true;
    }
    if(new_log_cnt[RULE_UDP] < log_length[RULE_UDP])
        new_log_cnt[RULE_UDP]++;
    spin_unlock(&log_lock);
}

void clear_log(unsigned proto){
    if(proto > PROTOCOL_SUPPORTED)
        return;
    spin_lock(&log_lock);
    switch(proto){
        case RULE_ALL:
            for(int i=0; i<PROTOCOL_SUPPORTED; i++){
                log_cnt[i] = 0;
                log_rewind[i] = 0;
                new_log_cnt[i] = 0;
                next_log_ptr[i] = 0;
            }
            break;
        default:
            log_cnt[proto] = 0;
            log_rewind[proto] = 0;
            new_log_cnt[proto] = 0;
            next_log_ptr[proto] = 0;
            break;
    }
    spin_unlock(&log_lock);
}
