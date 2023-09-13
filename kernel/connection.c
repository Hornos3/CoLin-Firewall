#include <linux/tcp.h>
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
void add_connection(void* pkt, unsigned proto, bool log){
	// IMPORTANT: this function WILL NOT check if the needed connection exists.
	// use find_con first if you want to add a connection!!!
	if(proto == RULE_ICMP){
	    if(con_count[RULE_ICMP] > max_con[RULE_ICMP]){
	        printk(KERN_ERR "Too many ICMP connections!");
	        return;
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
	}else {
        if (proto == RULE_TCP && con_count[RULE_TCP] >= max_con[RULE_TCP]) {
            printk(KERN_ERR "Too many TCP connections!");
            return;
        } else if (proto == RULE_UDP && con_count[RULE_UDP] >= max_con[RULE_UDP]) {
            printk(KERN_ERR "Too many UDP connections!");
            return;
        }
        connection *new_con = (connection *) kmalloc(sizeof(connection), GFP_KERNEL);
        new_con->proto = proto;
        new_con->log = log;
        if (proto == RULE_TCP) {
            memcpy(&new_con->header, ((tcp_pkt *) pkt)->myhdr, sizeof(tu_header));
            new_con->hash = ((tcp_pkt *) pkt)->hash;
            new_con->timeout = initial_timeout[RULE_TCP];
            new_con->last = this_moment_usec();
            // debug output
#ifdef DEBUG_MODE
            char *srcip = ip_ntoa(((tcp_pkt *) pkt)->myhdr->cliip);
            char *dstip = ip_ntoa(((tcp_pkt *) pkt)->myhdr->srvip);
            printk(KERN_INFO
            "Added a new tcp connection: src ip = %s"
            ", dst ip = %s, sport = %d, dport = %d, hash = %016lx\n", srcip, dstip,
                    ((tcp_pkt *) pkt)->myhdr->cliport, ((tcp_pkt *) pkt)->myhdr->srvport, new_con->hash);
            kfree(srcip);
            kfree(dstip);
#endif
        } else {
            memcpy(&new_con->header, ((udp_pkt *) pkt)->myhdr, sizeof(tu_header));
            new_con->hash = ((udp_pkt *) pkt)->hash;
            new_con->timeout = initial_timeout[RULE_UDP];
            new_con->last = this_moment_usec();
            // debug output
#ifdef DEBUG_MODE
            char *srcip = ip_ntoa(((udp_pkt *) pkt)->myhdr->cliip);
            char *dstip = ip_ntoa(((udp_pkt *) pkt)->myhdr->srvip);
            printk(KERN_INFO
            "Added a new udp connection: src ip = %s"
            ", dst ip = %s, sport = %d, dport = %d, hash = %016lx\n", srcip, dstip,
                    ((udp_pkt *) pkt)->myhdr->cliport, ((udp_pkt *) pkt)->myhdr->srvport, new_con->hash);
            kfree(srcip);
            kfree(dstip);
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
	}
}

void del_tu_connection(connection* con, bool timer){
    spin_lock(&con_lock);           // LOCK FOR LINKED LIST CHANGES
    if(timer)
        del_timer(&con->timer);
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