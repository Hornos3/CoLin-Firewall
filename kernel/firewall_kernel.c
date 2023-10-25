#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/timer.h>

#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/namei.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/udp.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>
#include <net/ip.h>

#include "log.h"
#include "rule.h"
#include "util.h"
#include "connection.h"
#include "statics.h"

MODULE_LICENSE("GPL"); 
MODULE_AUTHOR("lhy");

extern dev_t devid;
extern struct cdev cdev;
extern struct class* cls;
extern struct device* class_dev;
extern struct file_operations cdev_fops;

unsigned int tcp_handler(void* priv, struct sk_buff* skb, 
                         const struct nf_hook_state* state, 
                         unsigned hook_point){
    tcp_pkt pkg;
	struct iphdr* ip = ip_hdr(skb);			// ip header
    struct tcphdr* tcp = tcp_hdr(skb);		// tcp header
    connection* mayexist;
    
    pkg.header = tcp;
    pkg.length = skb->len;
    pkg.myhdr = get_tcp_header(ip, tcp);
    pkg.hash = tu_hash_header(pkg.myhdr);

    spin_lock_bh(&tcp_handler_lock);
    mayexist = (connection*)find_con(pkg.myhdr, pkg.hash, RULE_TCP);

    if(mayexist != NULL){
        mayexist->last = this_moment_usec();

        // This packet is not for the host, only need to check in PRE_ROUTING
        if(!is_local_addr(pkg.myhdr->srvip) && !is_local_addr(pkg.myhdr->cliip)){
            if(hook_point == HP_PRE_ROUTING){
                if(!check_and_update_status(mayexist, &pkg)){
                    if(mayexist->log)
                        new_tcp_log(&pkg, REJECT, hook_point);
                    goto tcp_drop;
                }
            }
        }else{  // need to check in PRE_ROUTING and POST_ROUTING
            if(!check_and_update_status(mayexist, &pkg)){
                if(mayexist->log)
                    new_tcp_log(&pkg, REJECT, hook_point);
                goto tcp_drop;
            }
        }

        if(mayexist->log)
            new_tcp_log(&pkg, ACCEPT, hook_point);
        if(mayexist->status == TCP_CON_CLOSED)
            del_tu_connection(mayexist, 1);     // when the connection closed, delete it directly
        else{
            reset_timer(mayexist, RULE_TCP, get_next_timeout(mayexist->timeout, RULE_TCP));
            mayexist->timeout = get_next_timeout(mayexist->timeout, RULE_TCP);
        }
        goto tcp_accept;
    }else{
        if(!pkg.header->syn){
            new_tcp_log(&pkg, REJECT, hook_point);
            goto tcp_drop;
        }
        unsigned match = match_rules(pkg.myhdr, hook_point, RULE_TCP);
        if(match & 2)
            new_tcp_log(&pkg, match & 1, hook_point);
        if(match & 1){
            connection* new_con = add_connection(&pkg, RULE_TCP, match & 2);
            if(!new_con)
                goto tcp_accept;    // when we cannot create a connection, NAT will be unavailable
            nat_config* nc = match_pat(pkg.myhdr->cliip, pkg.myhdr->srvip);
            if(nc){    // need to do pat
                pat_connection* new_pat = (pat_connection*)kmalloc(sizeof(pat_connection), GFP_KERNEL);
                new_pat->lan.ip = new_con->header.cliip;
                new_pat->lan.port = new_con->header.cliport;
                new_pat->wan.ip = new_con->header.srvport;
                new_pat->wan.port = new_con->header.srvport;
                new_pat->con = new_con;
                new_con->nat = new_pat;
                new_pat->gate.ip = nc->config.pc.wan;
                new_pat->gate.port = new_pat_port();
                connection* fake_con = add_fake_connection(new_con);
            }
            mayexist = new_con;
            goto tcp_accept;
        }
    }
    goto tcp_drop;
    tcp_accept:
    spin_unlock_bh(&tcp_handler_lock);
    kfree(pkg.myhdr);
    return NF_ACCEPT;
    tcp_drop:
    spin_unlock_bh(&tcp_handler_lock);
    kfree(pkg.myhdr);
    return NF_DROP;     // must be a complete TCP procedure
}

unsigned int udp_handler(void* priv, struct sk_buff* skb, 
                         const struct nf_hook_state* state, 
                         unsigned hook_point){
    udp_pkt pkg;
	struct iphdr* ip = ip_hdr(skb);			// ip header
    struct udphdr* udp = udp_hdr(skb);		// udp header
    connection* mayexist;
    
    pkg.header = udp;
    pkg.length = skb->len;
    pkg.myhdr = get_udp_header(ip, udp);
    pkg.hash = tu_hash_header(pkg.myhdr);

    spin_lock_bh(&udp_handler_lock);
    mayexist = (connection*)find_con(pkg.myhdr, pkg.hash, RULE_UDP);

    if(mayexist != NULL){
        mayexist->last = this_moment_usec();
        if(mayexist->log)
            new_udp_log(&pkg, ACCEPT, hook_point);
        reset_timer(mayexist, RULE_UDP, get_next_timeout(mayexist->timeout, RULE_UDP));
        mayexist->timeout = get_next_timeout(mayexist->timeout, RULE_UDP);
        goto udp_accept;
    }
    unsigned match = match_rules(pkg.myhdr, hook_point, RULE_UDP);
    if(match & 2)
        new_udp_log(&pkg, match & 1, hook_point);
    if(match & 1){
        connection* new_con = add_connection(&pkg, RULE_UDP, match & 2);
        if(!new_con)
            goto udp_accept;    // when we cannot create a connection, NAT will be unavailable
        nat_config* nc = match_pat(pkg.myhdr->cliip, pkg.myhdr->srvip);
        if(nc){    // need to do pat
            pat_connection* new_pat = (pat_connection*)kmalloc(sizeof(pat_connection), GFP_KERNEL);
            new_pat->lan.ip = new_con->header.cliip;
            new_pat->lan.port = new_con->header.cliport;
            new_pat->wan.ip = new_con->header.srvport;
            new_pat->wan.port = new_con->header.srvport;
            new_pat->con = new_con;
            new_con->nat = new_pat;
            new_pat->gate.ip = nc->config.pc.wan;
            new_pat->gate.port = new_pat_port();
            connection* fake_con = add_fake_connection(new_con);
        }
        mayexist = new_con;
        goto udp_accept;
    }
    goto udp_drop;
    udp_accept:
    spin_unlock_bh(&udp_handler_lock);
    kfree(pkg.myhdr);
    return NF_ACCEPT;
    udp_drop:
    spin_unlock_bh(&udp_handler_lock);
    kfree(pkg.myhdr);
    return NF_DROP;
}

unsigned int icmp_handler(void* priv, struct sk_buff* skb,
                          const struct nf_hook_state* state, 
                          unsigned hook_point){
    icmp_pkt pkg;
    struct iphdr* ip = ip_hdr(skb);
    struct icmphdr* icmp = icmp_hdr(skb);
    icmp_connection* mayexist;
    
    pkg.header = icmp;
    pkg.length = skb->len;
    pkg.myhdr = get_icmp_header(ip);
    pkg.hash = icmp_hash_header(pkg.myhdr);

    spin_lock_bh(&icmp_handler_lock);
    mayexist = (icmp_connection*)find_con(pkg.myhdr, pkg.hash, RULE_ICMP);
    if(mayexist != NULL){
        mayexist->last = this_moment_usec();
        if(mayexist->log)
            new_icmp_log(&pkg, ACCEPT, hook_point);
        reset_timer(mayexist, RULE_ICMP, get_next_timeout(mayexist->timeout, RULE_ICMP));
        mayexist->timeout = get_next_timeout(mayexist->timeout, RULE_ICMP);
        goto icmp_accept;
    }
    unsigned match = match_rules(pkg.myhdr, hook_point, RULE_ICMP);
    if(match & 2)
        new_icmp_log(&pkg, match & 1, hook_point);
    if(match & 1){
        add_connection(&pkg, RULE_ICMP, match & 2);
        goto icmp_accept;
    }
    goto icmp_drop;
    icmp_accept:
    spin_unlock_bh(&icmp_handler_lock);
    kfree(pkg.myhdr);
    return NF_ACCEPT;
    icmp_drop:
    spin_unlock_bh(&icmp_handler_lock);
    kfree(pkg.myhdr);
    return NF_DROP;
}

//the main monitor function
unsigned int packet_monitor(void * priv,struct sk_buff *skb,const struct nf_hook_state * state, int hp){
    struct iphdr* ip = ip_hdr(skb);
	switch(ip->protocol){
		case IPPROTO_TCP:
			return tcp_handler(priv, skb, state, hp);
			break;
		case IPPROTO_UDP:
			return udp_handler(priv, skb, state, hp);
			break;
		case IPPROTO_ICMP:
			return icmp_handler(priv, skb, state, hp);
			break;
		default:
			return NF_ACCEPT;
	}
}

unsigned int pre_routing_nat_hook(void *priv,struct sk_buff *skb,const struct nf_hook_state * state){
    return do_nat_in(priv, skb, state);
}

unsigned int post_routing_nat_hook(void *priv,struct sk_buff *skb,const struct nf_hook_state * state){
    return do_nat_out(priv, skb, state);
}

unsigned int pre_routing_hook(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
    return packet_monitor(priv, skb, state, HP_PRE_ROUTING);
}

unsigned int post_routing_hook(void * priv,struct sk_buff *skb,const struct nf_hook_state * state){
    return packet_monitor(priv, skb, state, HP_POST_ROUTING);
}

// nats
static struct nf_hook_ops pre_routing_nat={
 .hook = pre_routing_nat_hook,
 .pf = PF_INET,
 .hooknum = NF_INET_PRE_ROUTING,
 .priority = NF_IP_PRI_NAT_DST
};
static struct nf_hook_ops post_routing_nat = {
 .hook = post_routing_nat_hook,
 .pf = PF_INET,
 .hooknum = NF_INET_POST_ROUTING,
 .priority = NF_IP_PRI_NAT_SRC,
};
// connections
static struct nf_hook_ops pre_routing_op = {
    .hook = pre_routing_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST
};
static struct nf_hook_ops post_routing_op = {
    .hook = post_routing_hook,
    .pf = PF_INET,
    .hooknum = NF_INET_POST_ROUTING,
    .priority = NF_IP_PRI_FIRST
};

static int activate_hook(void){
    get_all_host_ips();
    // init etc files
    memset(rule_path, 0, sizeof(rule_path));
    struct file *file;
    file = filp_open("/etc/lhy_firewall/rule_path", O_RDWR, 0644);
    int ret;
    if (!IS_ERR(file)){
        ret = kernel_read(file, rule_path, 256, &file->f_pos);
        for(int i=0; i<256; i++){
            if(rule_path[i] == '\n')
                rule_path[i] = '\0';
        }
        if(ret < 0) {
            printk(KERN_ERR "Failed to read /etc/lhy_firewall/rule_path");
            return ret;
        }else
            filp_close(file, NULL);
    }else{
        printk(KERN_ERR "Failed to open config file /etc/lhy_firewall/rule_path");
        return -1;
    }
    // init lock
    spin_lock_init(&rule_lock);
    spin_lock_init(&con_lock);
    spin_lock_init(&log_lock);
    spin_lock_init(&tcp_handler_lock);
    spin_lock_init(&udp_handler_lock);
    spin_lock_init(&icmp_handler_lock);
    //spin_lock_init(&nat_lock);
    //netfilter hook
    printk("Netfilter hooks ready to register.\n");
    nf_register_net_hook(&init_net, &pre_routing_op);
    nf_register_net_hook(&init_net, &post_routing_op);
    nf_register_net_hook(&init_net, &pre_routing_nat);
    nf_register_net_hook(&init_net, &post_routing_nat);
	printk("All 5 hook points hooked.\n");
    
    //cdev register
    printk("Char device ready to register.\n");
    cdev_init(&cdev, &cdev_fops);
	alloc_chrdev_region(&devid, 2, 1, CDEV_NAME);
	printk("MAJOR char device number: %d\n", MAJOR(devid));
	printk("MINOR char device number: %d\n", MINOR(devid));
	cdev_add(&cdev, devid, 1);
    cls = class_create(THIS_MODULE, CDEV_NAME);
    class_dev = device_create(cls, NULL, devid, NULL, CDEV_NAME);

	// other things needed to be inited
	memset(rules, 0, sizeof(rules));
    for(int i=0; i<PROTOCOL_SUPPORTED; i++){
        memset(con_bucket[i], 0, sizeof(CON_SIZE(i)) * CONNECTION_BUCKET_CNT);
        logs[i] = kmalloc(LOG_SIZE(i) * log_length[i], GFP_KERNEL);
    }
    for(int i=0; i<HOOK_CNT; i++)
        for(int j=0; j<PROTOCOL_SUPPORTED; j++)
            default_strategy[i][j] = 3;
    load_all_rules(rule_path);
    return 0;
}

static void deactivate_hook(void){
    // hook unregister
    nf_unregister_net_hook(&init_net, &pre_routing_op);
    nf_unregister_net_hook(&init_net, &post_routing_op);
    nf_unregister_net_hook(&init_net, &pre_routing_nat);
    nf_unregister_net_hook(&init_net, &post_routing_nat);
    // wait for analyses to end
    spin_lock(&con_lock);
    spin_lock(&log_lock);
    spin_lock(&rule_lock);
    spin_unlock(&con_lock);
    spin_unlock(&log_lock);
    spin_unlock(&rule_lock);
    printk("5 hook points unregistered.\n");
    // destroy device
    device_destroy(cls, devid);
    class_destroy(cls);
    // cdev unregister
	cdev_del(&cdev);
	unregister_chrdev_region(devid, 1);
    printk("Char device unregistered.\n");
    // other things needed to be destroyed
    for(int i=0; i<PROTOCOL_SUPPORTED; i++){
        kfree(logs[i]);
    }
    del_all_timer();
    // save rules
    save_all_rules(rule_path);
    write_file("/etc/lhy_firewall/rule_path", rule_path, strlen(rule_path), true);
}

module_init(activate_hook);
module_exit(deactivate_hook);
