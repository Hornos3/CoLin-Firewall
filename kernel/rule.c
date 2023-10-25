#include <linux/types.h>
#include <linux/string.h>
#include <linux/spinlock.h>

#include "rule.h"
#include "util.h"
#include "statics.h"

#define DEFAULT_REJECT 0
#define DEFAULT_ACCEPT 1 

// void* header: icmp_header or tu_header
unsigned match_a_rule(void* header, fwrule* rule, unsigned proto){
    if(rule->protocol != proto)
        return 0xFF;
    if(proto == RULE_ICMP || proto == RULE_TCP || proto == RULE_UDP){
        if(!is_inCIDR(((icmp_header*)header)->cliip, &rule->src_ip) || 
           !is_inCIDR(((icmp_header*)header)->srvip, &rule->dst_ip))
            return 0xFF;
    }
    if(proto == RULE_TCP || proto == RULE_UDP){
        if((!is_inrange(((tu_header*)header)->cliport,
                        (port_range*)rule->src_ports, rule->src_port_len)) ||
           (!is_inrange(((tu_header*)header)->srvport,
                        (port_range*)rule->dst_ports, rule->dst_port_len)))
            return 0xFF;
    }
    return rule->action;
}

unsigned match_rules(void* header, unsigned int hook_point, unsigned proto){
    fwrule* ptr = rules[hook_point][proto];
    while(ptr != NULL){
        unsigned r = match_a_rule(header, ptr, proto);
        if(r != 0xFF)
            return r;
        ptr = ptr->next;
    }
    return default_strategy[hook_point][proto];
}

// This function can add a rule to a hook point.
// The position means where to insert the rule.
// Different protocols has different check lines,
// so a pointer is needed for positions for each rule.
bool add_rule(rule_tbi* tbi){
    // completely copy the content
    rule_tbi* from_user = (rule_tbi*)kmalloc(sizeof(rule_tbi), GFP_KERNEL);
    unsigned long ret = copy_from_user(from_user, tbi, sizeof(rule_tbi));
    if(ret){
        printk(KERN_ERR "Failed to copy from user, %s: line %d\n", __FILE__, __LINE__);
        return false;
    }
    fwrule* new_rule = (fwrule*)kmalloc(sizeof(fwrule), GFP_KERNEL);
    memcpy((void*)new_rule, (void*)&from_user->rule, sizeof(fwrule_user));
    if(from_user->rule.timeout)
        new_rule->timeout = this_moment_usec() / 1000000 + from_user->rule.timeout;
    else
        new_rule->timeout = 0;
    for(int i=0; i<PROTOCOL_SUPPORTED; i++)
        new_rule->next = new_rule->prev = NULL;

    spin_lock(&rule_lock);      // LOCK FOR LINKED LIST CHANGES
    inlink_rule(new_rule, from_user->insert_pos, from_user->rule.hook, from_user->rule.protocol);
    rule_cnt[from_user->rule.hook][from_user->rule.protocol]++;
    spin_unlock(&rule_lock);    // UNLOCK

    if(from_user->rule.timeout != 0) {
        timer_setup(&new_rule->timer, rule_timer_callback, 0);
        mod_timer(&new_rule->timer, jiffies + HZ * from_user->rule.timeout);
    }
#ifdef DEBUG_MODE
    unsigned tmp1 = ntohl(from_user->rule.src_ip.ip);
    unsigned tmp2 = ntohl(from_user->rule.dst_ip.ip);
    char* src_range = range_tostring((port_range*)from_user->rule.src_ports, from_user->rule.src_port_len);
    char* dst_range = range_tostring((port_range*)from_user->rule.dst_ports, from_user->rule.dst_port_len);
    if(from_user->rule.protocol == RULE_TCP || from_user->rule.protocol == RULE_UDP)
        printk(KERN_INFO "Successfully added a rule for hook %d, proto %d, source %pI4/%d, destination %pI4/%d, "
                         "source port %s, dest port %s, action %s, %s, position %d\n", from_user->rule.hook,
                         from_user->rule.protocol, &tmp1, from_user->rule.src_ip.mask, &tmp2,
                         from_user->rule.dst_ip.mask, src_range, dst_range,
                         (from_user->rule.action & 1) ? "ACCEPT" : "REJECT",
                         (from_user->rule.action & 2) ? "LOG" : "NO LOG", from_user->insert_pos);
    else
        printk(KERN_INFO "Successfully added a rule for hook %d, proto %d, source %pI4/%d, destination %pI4/%d, "
                         "action %s, %s position %d\n", from_user->rule.hook, from_user->rule.protocol, &tmp1,
                         from_user->rule.src_ip.mask, &tmp2, from_user->rule.dst_ip.mask,
                         (from_user->rule.action & 1) ? "ACCEPT" : "REJECT",
                         (from_user->rule.action & 2) ? "LOG" : "NO LOG", from_user->insert_pos);
    kfree(src_range);
    kfree(dst_range);
#endif
    return true;
}

void rule_timer_callback(struct timer_list* t){
    spin_lock(&rule_lock);
    fwrule* r = container_of(t, fwrule, timer);
    delink_rule(r);
    del_timer(t);
    spin_unlock(&rule_lock);
}

bool del_rule(rule_tbd* tbd){
    spin_lock(&rule_lock);          // LOCK FOR LINKED LIST CHANGES
    fwrule* ptr = rule_indexer(tbd->hp, tbd->proto, tbd->pos);
    if(ptr == NULL) {
        printk(KERN_INFO "Failed to delete the rule of hook %d, protocol %d, index %d.", tbd->hp, tbd->proto, tbd->pos);
        spin_unlock(&rule_lock);    // UNLOCK
        return false;
    }
    del_timer(&ptr->timer);
    delink_rule(ptr);
    spin_unlock(&rule_lock);        // UNLOCK
#ifdef DEBUG_MODE
    printk(KERN_INFO "Successfully deleted the rule of hook %d, protocol %d, index %d.", tbd->hp, tbd->proto, tbd->pos);
#endif
    return true;
}

bool del_all_rule(unsigned proto, unsigned hook){
    if(proto != PROTOCOL_SUPPORTED && hook != HOOK_CNT){
        rule_tbd tbd = {
            .proto = proto,
            .hp = hook,
            .pos = 1
        };
        while(rules[hook][proto])
            del_rule(&tbd);
        printk(KERN_INFO "Deleted all rules for %s in %s.\n", 
            proto_names[proto], hp_names[hook]);
        return true;
    }else if(proto == PROTOCOL_SUPPORTED && hook != HOOK_CNT){
        rule_tbd tbd = {
            .proto = proto,
            .hp = hook,
            .pos = 1
        };
        int p = 0;
        for(; p<PROTOCOL_SUPPORTED; p++){
            tbd.proto = p;
            while(rules[hook][p])
                del_rule(&tbd);
        }
        printk(KERN_INFO "Deleted all rules for all protocols in %s.\n",
            hp_names[hook]);
        return true;
    }else if(proto != PROTOCOL_SUPPORTED && hook == HOOK_CNT){
        rule_tbd tbd = {
            .proto = proto,
            .hp = hook,
            .pos = 1
        };
        int h = 0;
        for(; h<HOOK_CNT; h++){
            tbd.hp = h;
            while(rules[h][proto])
                del_rule(&tbd);
        }
        printk(KERN_INFO "Deleted all rules in all hook points for %s.\n",
            proto_names[proto]);
        return true;
    }else{
        rule_tbd tbd = {
            .proto = proto,
            .hp = hook,
            .pos = 1
        };
        int h = 0, p = 0;
        for(; h<HOOK_CNT; h++){
            tbd.hp = h;
            for(; p<PROTOCOL_SUPPORTED; p++){
                tbd.proto = p;
                while(rules[h][p])
                    del_rule(&tbd);
            }
        }
        printk(KERN_INFO "Deleted all rules in all hooks for all protocols.\n");
        return true;
    }
}

bool add_nat(nat_config* new_conf){
    if(nat_cnt == max_nat){
        printk("Too many nat rules!");
        return false;
    }
    nat_config* from_user = (nat_config*)kmalloc(sizeof(nat_config), GFP_KERNEL);
    if(copy_from_user(from_user, new_conf, sizeof(nat_config))){
        printk("Failed to read nat config from user!");
        return false;
    }
    if(from_user->NAT_mode != NAT_PAT){
        printk(KERN_ERR "NAT mode not supported.");
        kfree(from_user);
        return false;
    }

    spin_lock(&nat_lock);
    nat_cnt++;
    inlink_nat_rule(from_user);
    spin_unlock(&nat_lock);

#ifdef DEBUG_MODE
    unsigned tmp1 = ntohl(from_user->config.pc.lan.ip);
    unsigned tmp2 = ntohl(from_user->config.pc.wan);
    printk(KERN_INFO "Successfully added a nat rule for lan %pI4/%d, wan %pI4\n", &tmp1,
            from_user->config.pc.lan.mask, &tmp2);
#endif
    return true;
}

bool del_nat(nat_config* target){
    if(nat_cnt == 0)
        return false;
    spin_lock(&nat_lock);
    nat_config* t = nat_rule_indexer(target);
    if(!t){
        spin_unlock(&nat_lock);
        return false;
    }
#ifdef DEBUG_MODE
    unsigned tmp1 = ntohl(t->config.pc.lan.ip);
    unsigned tmp2 = ntohl(t->config.pc.wan);
    printk(KERN_INFO "Successfully deleted a nat rule for lan %pI4/%d, wan %pI4\n", &tmp1,
            t->config.pc.lan.mask, &tmp2);
#endif
    delink_nat_rule(t);
    spin_unlock(&nat_lock);
    return true;
}
