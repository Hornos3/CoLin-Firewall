#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/udp.h>
#include <net/tcp.h>
#include <linux/icmp.h>
#include <linux/timer.h>
#include <linux/types.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include <linux/spinlock.h>

#include "connection.h"
#include "statics.h"

// Check if there exists a connection including this packet
// the hash value of a connection is got through procedures below:
// 1. calculate the hash value for ips and ports
// 2. swap two peers and calculate again
// 3. xor two hash values
// All the connection infos is saved in a 256-length bucket, the index of the 
// bucket is the highest 8 bit of connections' hash values. Through calculations 
// above, when searching a connection by a packet is needed, there will be no
// need to search twice where the first time calculating the hash value of ips 
// and ports of packet and the second time swapping the peers and calculating 
// again. JUST SWAP AND GET THE HASH!!!

// #define STRICT_CHECK

void* find_con(void* pkt, size_t hash, unsigned int proto){
	int index = hash >> (WORD_SIZE - CONNECTION_BUCKET_BITS);
	if(proto == RULE_ICMP){
	    icmp_header* pkg = (icmp_header*)pkt;
		icmp_connection* ptr = con_bucket[RULE_ICMP][index];	// get the bucket
		while(ptr != NULL){
			if(ptr->hash != hash){
				ptr = ptr->next;
				continue;
			}
			#ifdef STRICT_CHECK
			if(compare_icmp_hdr_strict(pkg, &(ptr->header)))
				return ptr;
			ptr = ptr->next;
			#else
			return ptr;
			#endif
		}
	}else if(proto == RULE_TCP || proto == RULE_UDP){
	    tu_header* pkg = (tu_header*)pkt;
        connection* ptr;
        if(proto == RULE_TCP)
            ptr = con_bucket[RULE_TCP][index];	// get the bucket
        else
            ptr = con_bucket[RULE_UDP][index];
		while(ptr != NULL){
			if(ptr->hash != hash){
				ptr = ptr->next;
				continue;
			}
			#ifdef STRICT_CHECK
			if(compare_tu_hdr_strict(pkg, &(ptr->header)))
				return ptr;
			ptr = ptr->next;
			#else
			return ptr;
			#endif
		}
	}
	return NULL;
}


// A connection is timeout, will be deleted
void icmp_timer_callback(struct timer_list* t){
    icmp_connection* con = container_of(t, icmp_connection, timer);
    if(this_moment_usec() - (con->timeout - 1) * 1000000 >= con->last) {
        del_timer(t);
        del_icmp_connection(con, false);
    }
}

void tu_timer_callback(struct timer_list* t){
    connection* con = container_of(t, connection, timer);
    if(this_moment_usec() - (con->timeout - 1) * 1000000 >= con->last) {
        del_timer(t);
        del_tu_connection(con, false);
    }
}

// add a connection.
// void* pkt: tcp_pkt, udp_pkt or icmp_pkt
// proto: protocol id, use RULE_...
void* add_connection(void* pkt, unsigned proto, bool log){
	// IMPORTANT: this function WILL NOT check if the needed connection exists.
	// use find_con first if you want to add a connection!!!
	if(proto == RULE_ICMP){
	    if(con_count[RULE_ICMP] > max_con[RULE_ICMP]){
	        printk(KERN_ERR "Too many ICMP connections!");
	        return NULL;
	    }
	    icmp_pkt* pkg = (icmp_pkt*)pkt;
	    icmp_connection* new_con = (icmp_connection*)kmalloc(sizeof(icmp_connection), GFP_KERNEL);
	    memcpy(&new_con->header, pkg->myhdr, sizeof(icmp_header));
	    new_con->type = pkg->header->type;
	    new_con->hash = pkg->hash;
        new_con->log = log;
        new_con->timeout = initial_timeout[RULE_ICMP];
        new_con->last = this_moment_usec();
	    
	    spin_lock(&con_lock);       // LOCK FOR LINKED LIST CHANGES
	    inlink_icmp(new_con, (icmp_connection**)&con_bucket[RULE_ICMP][new_con->hash >> (WORD_SIZE - CONNECTION_BUCKET_BITS)]);
	    timer_setup(&new_con->timer, icmp_timer_callback, 0);
	    mod_timer(&new_con->timer, jiffies + HZ * initial_timeout[RULE_ICMP]);
	    con_count[RULE_ICMP]++;
	    spin_unlock(&con_lock);     // UNLOCK
	    // debug output
	    #ifdef DEBUG_MODE
	    char* srcip = ip_ntoa(pkg->myhdr->cliip);
	    char* dstip = ip_ntoa(pkg->myhdr->srvip);
	    printk(KERN_INFO "Added a new icmp connection: src ip = %s, dst ip = %s, hash = %016lx",
               srcip, dstip, pkg->hash);
	    kfree(srcip);
	    kfree(dstip);
        #endif
        return new_con;
	}else {
        if (proto == RULE_TCP && con_count[RULE_TCP] >= max_con[RULE_TCP]) {
            printk(KERN_ERR "Too many TCP connections!");
            return NULL;
        } else if (proto == RULE_UDP && con_count[RULE_UDP] >= max_con[RULE_UDP]) {
            printk(KERN_ERR "Too many UDP connections!");
            return NULL;
        }
        connection *new_con = (connection *) kmalloc(sizeof(connection), GFP_KERNEL);
        new_con->proto = proto;
        new_con->log = log;
        new_con->nat = NULL;
        new_con->is_nat_con = 0;
        new_con->con_ptr = NULL;
        if (proto == RULE_TCP) {
            memcpy(&new_con->header, ((tcp_pkt *) pkt)->myhdr, sizeof(tu_header));
            new_con->hash = ((tcp_pkt *) pkt)->hash;
            new_con->timeout = initial_timeout[RULE_TCP];
            new_con->last = this_moment_usec();
            new_con->status = TCP_CON_SYN;
            // debug output
#ifdef DEBUG_MODE
            printk(KERN_INFO
            "Added a new tcp connection: src ip = %pI4"
            ", dst ip = %pI4, sport = %d, dport = %d, hash = %016lx\n", &((tcp_pkt *) pkt)->myhdr->cliip,
                    &((tcp_pkt *) pkt)->myhdr->srvip, ((tcp_pkt *) pkt)->myhdr->cliport,
                    ((tcp_pkt *) pkt)->myhdr->srvport, new_con->hash);
#endif
        } else {
            memcpy(&new_con->header, ((udp_pkt *) pkt)->myhdr, sizeof(tu_header));
            new_con->hash = ((udp_pkt *) pkt)->hash;
            new_con->timeout = initial_timeout[RULE_UDP];
            new_con->last = this_moment_usec();
            // debug output
#ifdef DEBUG_MODE
            printk(KERN_INFO
            "Added a new udp connection: src ip = %pI4"
            ", dst ip = %pI4, sport = %d, dport = %d, hash = %016lx\n", &((udp_pkt *) pkt)->myhdr->cliip,
                    &((udp_pkt *) pkt)->myhdr->srvip, ((udp_pkt *) pkt)->myhdr->cliport,
                    ((udp_pkt *) pkt)->myhdr->srvport, new_con->hash);
#endif
        }
        spin_lock(&con_lock);       // LOCK FOR LINKED LIST CHANGES
        if (new_con->proto == RULE_TCP){
            inlink_tu(new_con, (connection **) &con_bucket[RULE_TCP][new_con->hash >> (WORD_SIZE - CONNECTION_BUCKET_BITS)]);
            timer_setup(&new_con->timer, tu_timer_callback, 0);
            mod_timer(&new_con->timer, jiffies + HZ * initial_timeout[RULE_TCP]);
        }else{
            inlink_tu(new_con, (connection **) &con_bucket[RULE_UDP][new_con->hash >> (WORD_SIZE - CONNECTION_BUCKET_BITS)]);
            timer_setup(&new_con->timer, tu_timer_callback, 0);
            mod_timer(&new_con->timer, jiffies + HZ * initial_timeout[RULE_UDP]);
        }

        if(proto == RULE_TCP)
            con_count[RULE_TCP]++;
        else
            con_count[RULE_UDP]++;
        spin_unlock(&con_lock);     // UNLOCK
        return new_con;
	}
}

bool check_and_update_status(connection* con, tcp_pkt* pkg){
    if(pkg->header->rst){
        con->status = TCP_CON_CLOSED;
        return 1;
    }
    switch(con->status){
        case TCP_CON_SYN:
            if(pkg->header->ack && pkg->header->syn){
                con->status = TCP_CON_SYNACK;
                return 1;
            }else if(pkg->header->syn)  // repeated packet
                return 1;
            else
                goto undefined;
        case TCP_CON_SYNACK:
            if(pkg->header->ack){
                con->status = TCP_CON_CONNECTED;
                return 1;
            }else if(pkg->header->ack && pkg->header->syn)  // repeated packet
                return 1;
            else
                goto undefined;
        case TCP_CON_CONNECTED:
            if(pkg->header->fin && pkg->header->ack){
                con->status = TCP_CON_FIN_1;
                return 1;
            }else
                return 1;
        case TCP_CON_FIN_1:
            if(pkg->header->ack){
                con->status = TCP_CON_ACK_1;
                return 1;
            }else if(pkg->header->fin && pkg->header->ack)  // repeated packet
                return 1;
            else
                goto undefined;
        case TCP_CON_ACK_1:
            if(pkg->header->fin && pkg->header->ack){
                con->status = TCP_CON_FIN_2;
                return 1;
            }else if(pkg->header->ack)  // repeated packet
                return 1;
            else
                goto undefined;
        case TCP_CON_FIN_2:
            if(pkg->header->ack){
                con->status = TCP_CON_CLOSED;
                return 1;
            }else if(pkg->header->fin && pkg->header->ack)  // repeated packet
                return 1;
            else
                goto undefined;
        case TCP_CON_CLOSED:
            if(pkg->header->ack)    // repeated packet
                return 1;
            else
                goto undefined;
        default:
            return 0;
    }
    undefined:
    return 0;
}

connection* add_fake_connection(connection* con){
    if(!con)
        return NULL;
    if(!con->nat)
        return NULL;
    tu_header fake_header;
    fake_header.cliip = con->header.srvip;
    fake_header.srvip = con->nat->gate.ip;
    fake_header.cliport = con->header.srvport;
    fake_header.srvport = con->nat->gate.port;

    if(con->proto == RULE_TCP){
        tcp_pkt pkg;
        pkg.myhdr = &fake_header;
        pkg.hash = tu_hash_header(&fake_header);
        connection* fake_con = (connection*)add_connection(&pkg, RULE_TCP, con->log);
        fake_con->is_nat_con = 1;
        fake_con->nat = con->nat;
        fake_con->con_ptr = con;
        con->con_ptr = fake_con;
        return fake_con;
    }else if(con->proto == RULE_UDP){
        udp_pkt pkg;
        pkg.myhdr = &fake_header;
        pkg.hash = tu_hash_header(&fake_header);
        connection* fake_con = (connection*)add_connection(&pkg, RULE_UDP, con->log);
        fake_con->is_nat_con = 1;
        fake_con->nat = con->nat;
        fake_con->con_ptr = con;
        con->con_ptr = fake_con;
        return fake_con;
    }
}

void del_tu_connection(connection* con, bool timer){
    spin_lock(&con_lock);           // LOCK FOR LINKED LIST CHANGES
    if(timer)
        del_timer(&con->timer);
    if(con->nat && con->con_ptr && !con->is_nat_con){
        del_tu_connection(con->con_ptr, timer);
        con->con_ptr = NULL;
    }
    if(con->proto == RULE_TCP) {
        delink_tu(con, (connection **) &con_bucket[RULE_TCP][con->hash >> (WORD_SIZE - CONNECTION_BUCKET_BITS)]);
        con_count[RULE_TCP]--;
    }else{
        delink_tu(con, (connection **) &con_bucket[RULE_UDP][con->hash >> (WORD_SIZE - CONNECTION_BUCKET_BITS)]);
        con_count[RULE_UDP]--;
    }
    spin_unlock(&con_lock);         // UNLOCK
    #ifdef DEBUG_MODE
    char* srcip = ip_ntoa(con->header.cliip);
    char* dstip = ip_ntoa(con->header.srvip);
    if(con->proto == RULE_TCP)
        printk("Deleted a tcp connection: src ip = %s, dst ip = %s, "
            "sport = %d, dport = %d\n",
            srcip, dstip, con->header.cliport, con->header.srvport);
    else if(con->proto == RULE_UDP){
        printk("Deleted a udp connection: src ip = %s, dst ip = %s, "
            "sport = %d, dport = %d\n",
            srcip, dstip, con->header.cliport, con->header.srvport);
    }
    kfree(srcip);
    kfree(dstip);
    #endif
    kfree(con);
}

void del_icmp_connection(icmp_connection* con, bool timer){
    spin_lock(&con_lock);           // LOCK FOR LINKED LIST CHANGES
    if(timer)
        del_timer(&con->timer);
    delink_icmp(con, (icmp_connection**)&con_bucket[RULE_ICMP][con->hash >> (WORD_SIZE - CONNECTION_BUCKET_BITS)]);
    con_count[RULE_ICMP]--;
    spin_unlock(&con_lock);         // UNLOCK
    #ifdef DEBUG_MODE
    char* srcip = ip_ntoa(con->header.cliip);
    char* dstip = ip_ntoa(con->header.srvip);
    printk("Deleted a icmp connection: src ip = %s, dst ip = %s", srcip, dstip);
    kfree(srcip);
    kfree(dstip);
    #endif
    kfree(con);
}

void reset_timer(void* con, unsigned proto, unsigned time){
    if(proto == RULE_TCP || proto == RULE_UDP){
        del_timer(&((connection*)con)->timer);
        mod_timer(&((connection*)con)->timer, jiffies + HZ * time);
    }else{
        del_timer(&((icmp_connection*)con)->timer);
        mod_timer(&((icmp_connection*)con)->timer, jiffies + HZ * time);
    }
}

unsigned get_next_timeout(unsigned last_timeout, unsigned proto){
    if(proto == RULE_TCP){
        if(TCP_con_timeout_fixed || last_timeout >= connection_max_timeout[proto])
            return last_timeout;
        else
            return last_timeout + 1;    // timeout increases linearly
    }else if(proto == RULE_UDP){
        if(UDP_con_timeout_fixed || last_timeout >= connection_max_timeout[proto])
            return last_timeout;
        else
            return last_timeout + 1;
    }else{
        return last_timeout;
    }
}


// from wan to lan, should use PRE_ROUTING and change dest
unsigned int do_nat_in(void* priv, struct sk_buff* skb, const struct nf_hook_state* state){ // wan to lan
    struct iphdr* ip = ip_hdr(skb);
    connection* mayexist;
    if(ip->protocol == IPPROTO_TCP){
        tcp_pkt pkg;
        struct iphdr* ip = ip_hdr(skb);			// ip header
        struct tcphdr* tcp = tcp_hdr(skb);		// tcp header

        pkg.header = tcp;
        pkg.length = skb->len;
        pkg.myhdr = get_tcp_header(ip, tcp);
        pkg.hash = tu_hash_header(pkg.myhdr);

        spin_lock_bh(&tcp_handler_lock);
        mayexist = (connection*)find_con(pkg.myhdr, pkg.hash, RULE_TCP);
        if(mayexist != NULL && mayexist->nat){
            // this packet is not from wan to lan, skipped.
            if(!(ip->saddr == ntohl(mayexist->header.cliip) && ip->daddr == ntohl(mayexist->nat->gate.ip))) {
                spin_unlock_bh(&tcp_handler_lock);
                return NF_ACCEPT;
            }
            if(!mayexist->is_nat_con){
                printk(KERN_ERR "[in] Non-fake connection found for lan to wan.");
                spin_unlock_bh(&tcp_handler_lock);
                return NF_ACCEPT;
            }

            unsigned iphdr_len = ip->ihl * 4;
            unsigned iphdr_totlen = ntohs(ip->tot_len);
            ip->daddr = ntohl(mayexist->con_ptr->header.cliip);
            ip->check = 0;
            ip->check = ip_fast_csum(ip, ip->ihl);

            tcp->dest = htons(mayexist->con_ptr->header.cliport);
            tcp->check = 0;
            skb->csum = csum_partial((unsigned char *) tcp, iphdr_totlen - iphdr_len, 0);
            tcp->check = csum_tcpudp_magic(ip->saddr, ip->daddr, iphdr_totlen - iphdr_len, ip->protocol, skb->csum);
        }else{
            spin_unlock_bh(&tcp_handler_lock);
            return NF_ACCEPT;
        }
        spin_unlock_bh(&tcp_handler_lock);
        return NF_ACCEPT;
    }else if(ip->protocol == IPPROTO_UDP){
        udp_pkt pkg;
        struct iphdr* ip = ip_hdr(skb);			// ip header
        struct udphdr* udp = udp_hdr(skb);		// tcp header

        pkg.header = udp;
        pkg.length = skb->len;
        pkg.myhdr = get_udp_header(ip, udp);
        pkg.hash = tu_hash_header(pkg.myhdr);

        spin_lock_bh(&udp_handler_lock);
        mayexist = (connection*)find_con(pkg.myhdr, pkg.hash, RULE_UDP);
        if(mayexist != NULL && mayexist->nat){
            if(!(ip->saddr == ntohl(mayexist->header.cliip) && ip->daddr == ntohl(mayexist->nat->gate.ip))) {
                spin_unlock_bh(&tcp_handler_lock);
                return NF_ACCEPT;
            }
            if(!mayexist->is_nat_con){
                printk(KERN_ERR "[in] Non-fake connection found for lan to wan.");
                spin_unlock_bh(&udp_handler_lock);
                return NF_ACCEPT;
            }

            unsigned iphdr_len = ip->ihl * 4;
            unsigned iphdr_totlen = ntohs(ip->tot_len);
            ip->daddr = ntohl(mayexist->con_ptr->header.cliip);
            ip->check = 0;
            ip->check = ip_fast_csum(ip, ip->ihl);

            udp->dest = htons(mayexist->con_ptr->header.cliport);
            udp->check = 0;
            skb->csum = csum_partial((unsigned char *) udp, iphdr_totlen - iphdr_len, 0);
            udp->check = csum_tcpudp_magic(ip->saddr, ip->daddr, iphdr_totlen - iphdr_len, ip->protocol, skb->csum);
        }else{
            spin_unlock_bh(&udp_handler_lock);
            return NF_ACCEPT;
        }
        spin_unlock_bh(&udp_handler_lock);
        return NF_ACCEPT;
    }else
        return NF_ACCEPT;
}

// from lan to wan, should use POST_ROUTING and change source
unsigned int do_nat_out(void* priv, struct sk_buff* skb, const struct nf_hook_state* state){ // lan to wan
    struct iphdr* ip = ip_hdr(skb);
    connection* mayexist;
    if(ip->protocol == IPPROTO_TCP){
        tcp_pkt pkg;
        struct iphdr* ip = ip_hdr(skb);			// ip header
        struct tcphdr* tcp = tcp_hdr(skb);		// tcp header

        pkg.header = tcp;
        pkg.length = skb->len;
        pkg.myhdr = get_tcp_header(ip, tcp);
        pkg.hash = tu_hash_header(pkg.myhdr);

        spin_lock_bh(&tcp_handler_lock);
        mayexist = (connection*)find_con(pkg.myhdr, pkg.hash, RULE_TCP);
        if(mayexist != NULL && mayexist->nat){
            if(ip->saddr != ntohl(mayexist->header.cliip)) {   // wan to lan
                spin_unlock_bh(&tcp_handler_lock);
                return NF_ACCEPT;
            }
            if(mayexist->is_nat_con){
                printk(KERN_ERR "[out] Fake connection found for wan to lan.");
                spin_unlock_bh(&tcp_handler_lock);
                return NF_ACCEPT;
            }

            unsigned iphdr_len = ip->ihl * 4;
            unsigned iphdr_totlen = ntohs(ip->tot_len);
            ip->saddr = ntohl(mayexist->nat->gate.ip);
            ip->check = 0;
            ip->check = ip_fast_csum(ip, ip->ihl);

            tcp->source = htons(mayexist->nat->gate.port);
            tcp->check = 0;
            skb->csum = csum_partial((unsigned char*)tcp, iphdr_totlen - iphdr_len, 0);
            tcp->check = csum_tcpudp_magic(ip->saddr, ip->daddr, iphdr_totlen - iphdr_len, ip->protocol, skb->csum);
        }else{
            spin_unlock_bh(&tcp_handler_lock);
            return NF_ACCEPT;
        }
        spin_unlock_bh(&tcp_handler_lock);
        return NF_ACCEPT;
    }else if(ip->protocol == IPPROTO_UDP){
        udp_pkt pkg;
        struct iphdr* ip = ip_hdr(skb);			// ip header
        struct udphdr* udp = udp_hdr(skb);		// tcp header

        pkg.header = udp;
        pkg.length = skb->len;
        pkg.myhdr = get_udp_header(ip, udp);
        pkg.hash = tu_hash_header(pkg.myhdr);

        spin_lock_bh(&udp_handler_lock);
        mayexist = (connection*)find_con(pkg.myhdr, pkg.hash, RULE_UDP);
        if(mayexist != NULL && mayexist->nat){
            if(ip->saddr != ntohl(mayexist->header.cliip)) {
                spin_unlock_bh(&udp_handler_lock);
                return NF_ACCEPT;
            }
            if(mayexist->is_nat_con){
                printk(KERN_ERR "[out] Fake connection found for wan to lan.");
                spin_unlock_bh(&udp_handler_lock);
                return NF_ACCEPT;
            }

            unsigned iphdr_len = ip->ihl * 4;
            unsigned iphdr_totlen = ntohs(ip->tot_len);
            ip->saddr = ntohl(mayexist->nat->gate.ip);
            ip->check = 0;
            ip->check = ip_fast_csum(ip, ip->ihl);

            udp->check = 0;
            udp->source = ntohs(mayexist->nat->gate.port);
            skb->csum = csum_partial((unsigned char*)udp, iphdr_totlen - iphdr_len, 0);
            udp->check = csum_tcpudp_magic(ip->saddr, ip->daddr, iphdr_totlen - iphdr_len, ip->protocol, skb->csum);
        }else{
            spin_unlock_bh(&udp_handler_lock);
            return NF_ACCEPT;
        }
        spin_unlock_bh(&udp_handler_lock);
        return NF_ACCEPT;
    }else
        return NF_ACCEPT;
}