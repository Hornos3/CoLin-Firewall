#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/blk_types.h>

#include "statics.h"

dev_t devid = 0;
struct cdev cdev = {};
struct class* cls = NULL;
struct device* class_dev = NULL;

int cdev_open(struct inode* inode, struct file* file){
    printk("Char device opened\n");
	return 0;
}

ssize_t cdev_read(struct file* file, char* __user buf, size_t size, loff_t* ppos){ return 0; }
ssize_t cdev_write(struct file* file, const char* __user buf, size_t size, loff_t* ppos){ return 0; }

// Main operation function for this char device.
// Usage:
// command_code = 0b0101101: return pat rules, saved in (char*)arg;
// command_code = 0b0101110: add/delete a pat rule. arg: nat_config*, the last bit 0 for add,
//                           1 for delete
// command_code = 0b0101111: set the config.
// command_code = 0b0111101: set the file for saving rules, the kernel will try to
//                           find the file and create it. If failed, path will remain
//                           unchanged.
// command_code = 0b0111110: get the file saving the rules, saved in (char*) arg.
// command_code = 0b0111111: add a rule for a hook
//                           arg: rule_tbi*
// command_code = 0b1111000: return monitoring connections. Saved in (void*)arg.
//                           arg: for a pointer, the last 3 bit can be used for other
//                           use. 000 for tcp, 001 for udp, 010 for icmp, 011 for
//                           all protocols.
// command_code = 0b1111001: write connections into a file, filename is in (void*)arg.
//                           the last 3 bit has the same function as 0b1111000.
// command_code = 0b1111010: clear logs, arg = RULE_xxx, clear logs for a 
//                           certain protocol; arg = 3, clear all.
// command_code = 0b1111011: return ALL the saved logs. Saved in (void*)arg.
//                           THIS COMMAND IS STRONGLY NOT RECOMMENDED FOR THE COPY
//                           CONTENT MAY BE HUGE WHICH REDUCES THE EFFICIENCY OF
//                           THIS FIREWALL.
// command_code = 0b1111100: write ALL logs into a file, filename is in (void*)arg.
// command_code = 0b1111101: return logs newly generated after last return.
//                           THIS COMMAND IS RECOMMENDED FOR USER MANAGEMENT ELFS.
// command_code = 0b1111110: return current configs of this firewall, arg specifies
//                           what config to return (See statics.h).
// command_code = 0b1111111: dump/load all rules into/from a file, filename is in
//                           (void*)arg, the LSB of arg: 0 for dump, 1 for load.

// command_code = 0b......0: instruction for PRE_ROUTING hook.
// command_code = 0b......1: instruction for POST_ROUTING hook.

// command_code = 0b..00...: instruction for all protocols.
// command_code = 0b..01...: instruction for tcp.
// command_code = 0b..10...: instruction for udp.
// command_code = 0b..11...: instruction for icmp.

// command_code = 0b100.....: set default activity
//     (bit0=0 for default rejection, =1 for default acception)
//     (bit1=0. for default no log, =1. for default log)
//     (bit7=0 for set, =1 for get from return value);
// command_code = 0b01.....: return rules(do not support all rules, you can
//                           only get rules for one hook and one protocol once),
//                           saved in (void*)arg.
// command_code = 0b10.....: delete a rule
//     arg: the struct of a rule, if NULL, then will delete all the rules
//          (default not included). Else, the kernel will find it and delete it.
#define CODE_PROTO ((command_code >> 3) & 3)
#define CODE_HOOK (command_code & 7)
#define PTR(x) ((x) ^ (x & 0b111))      // clear the last 3 bits
#define LSB(x) ((x) & 0b111)
long cdev_ioctl(struct file* file, unsigned int command_code, 
                unsigned long arg){
    // printk("Command code = %d, arg = %lx\n", command_code, arg);
    unsigned* configs[] = {
            &TCP_syn_timeout,
            &TCP_fin_timeout,
            &initial_timeout[RULE_TCP],
            &initial_timeout[RULE_UDP],
            &initial_timeout[RULE_ICMP],
            &connection_max_timeout[RULE_TCP],
            &connection_max_timeout[RULE_UDP],
            &connection_max_timeout[RULE_ICMP],
            &TCP_con_timeout_fixed,
            &UDP_con_timeout_fixed,
            &max_con[RULE_TCP],
            &max_con[RULE_UDP],
            &max_con[RULE_ICMP],
            &log_length[RULE_TCP],
            &log_length[RULE_UDP],
            &log_length[RULE_ICMP],
            &max_rule,
            &max_nat
    };
    // handle control codes;
    switch(command_code){
        case 0x2D:{
            return extract_nat_configs((nat_config_touser*)arg, max_nat);
        }
        case 0x2E:{
            if(!LSB(arg))
                return add_nat((nat_config*)PTR(arg)) ? 0 : -1;
            nat_config nc;
            if(copy_from_user(&nc, (void*)(arg ^ (arg & 1)), sizeof(nat_config))){
                printk(KERN_ERR "Failed to get nat config from user.");
                return -1;
            }
            return del_nat(&nc) ? 0 : -1;
        }
        case 0x2F:{
            config_user config;
            if(copy_from_user(&config, (config_user*)arg, sizeof(config_user))){
                printk(KERN_ERR "Failed to get config value from user.");
                return -1;
            }
            if(config.id > sizeof(configs) / sizeof(unsigned*)){
                printk(KERN_ERR "Config id invalid: %d\n", config.id);
                return -1;
            }
            *(configs[config.id]) = config.value;
            printk(KERN_INFO "Config %d set to %d", config.id, *(configs[config.id]));
            return 0;
        }
        case 0x3D: {
            char *new_path = get_string_from_user((char *) arg);    // let the check finished by user programs.
            strncpy(rule_path, new_path, 256);
            printk(KERN_INFO "Rule path changed to %s\n", rule_path);
            kfree(new_path);
            return 0;
        }
        case 0x3E: {
            unsigned long ret = copy_to_user((void *) arg, rule_path, strlen(rule_path));
            return strlen(rule_path);
        }
        case 0x3F: {
            unsigned ret = add_rule((rule_tbi *) arg);
            return ret;
        }
        // connection: struct + icmp connections + tcp/udp connections
        case 0x78:     // 0b11000, if copy failed, return -1
        case 0x79:{    // 0b11001, if write failed, return -1
            con_touser* to_user = get_connections(arg);
            if(command_code == 0x78){
                if(copy_to_user((void*)PTR(arg), to_user, to_user->total_size) != 0)
                    return -1;
                // printk(KERN_INFO "Connection data sent to user: %zd bytes\n", to_user->total_size);
                break;
            }else{
                char* filename = get_string_from_user((char*)PTR(arg));
                return write_file(filename, (char*)to_user, to_user->total_size, true);
            }
        }
        case 0x7A:      // 0b11010
            clear_log(arg);
            return 0;
        // logs: struct + icmp logs + tcp logs + udp logs
        case 0x7B:      // 0b11011, if copy failed, return -1
        case 0x7C:{     // 0b11100, if write failed, return -1
            log_touser* to_user = get_logs(arg);
            if(command_code == 0x7B){
                if(copy_to_user((void*)PTR(arg), (char*)to_user, to_user->total_size) != 0)
                    return -1;
                // printk(KERN_INFO "Log data sent to user: %zd bytes\n", to_user->total_size);
                break;
            }else if(command_code == 0x7C){
                char* filename = get_string_from_user((char*)PTR(arg));
                return write_file(filename, (char*)to_user, to_user->total_size, true);
            }
        }
        case 0x7D:{
            log_touser* to_user = get_new_logs(arg);
            if(copy_to_user((void*)PTR(arg), (char*)to_user, to_user->total_size) != 0)
                return -1;
            // printk(KERN_INFO "Log data sent to user: %zd bytes\n", to_user->total_size);
            return 0;
        }
        case 0x7E:{
            if(arg >= sizeof(configs) / sizeof(long*) || arg < 0)
                return -1;
            return *(configs[arg]);
        }
        default:
            break;
    }
    switch(command_code >> 5){
        case 4:     // 0b00.....
            if(arg & 0b10000000) {
                arg ^= 0b10000000;
                return default_strategy[CODE_HOOK][CODE_PROTO];
            }
            else
                default_strategy[CODE_HOOK][CODE_PROTO] = arg & ((1 << DEFAULT_OPTIONS) - 1);
            break;
        case 1: {   // 0b01.....
            void *data = get_rule_for_output(CODE_HOOK, CODE_PROTO);   // reset variables
            unsigned long ret = copy_to_user((void *) arg, (void *) data, RULEOUT_SIZE(data));
            if (ret) {
                printk("Failed to copy %ld bytes.", ret);
                kfree(data);
                return -1;
            }
            // printk(KERN_INFO "Rule data sent to user: %ld bytes", RULEOUT_SIZE(data));
            kfree(data);
            return 0;
        }
        case 2:     // 0b10xx...
            if(!arg)    // delete all rules
                del_all_rule(CODE_PROTO, CODE_HOOK);
            else{
                rule_tbd tbd;
                if(copy_from_user((void*)&tbd, (char*)arg, sizeof(tbd)) != 0)
                    return -1;
                del_rule(&tbd);
            }
    }
    return 0;
}

// Define file operations
struct file_operations cdev_fops = {
    .open = cdev_open,
    .read = cdev_read,
    .write = cdev_write,
	.unlocked_ioctl = cdev_ioctl,
};

con_touser* get_connections(unsigned long arg){
    spin_lock(&con_lock);    // it may be a lock for a long time
    unsigned proto = LSB(arg);
    con_touser* to_user;
    if(proto == RULE_ALL){
        unsigned off[3] = {sizeof(con_touser)};
        off[1] = off[0] + sizeof(tu_con_touser) * con_count[RULE_TCP];
        off[2] = off[1] + sizeof(tu_con_touser) * con_count[RULE_UDP];
        size_t size_needed = off[2] + sizeof(icmp_con_touser) * con_count[RULE_ICMP];
        if(size_needed > MAX_CON_BUFLEN(proto)){
            printk(KERN_ERR "Copy size abnormal, there may be a bug in this kernel module! size: %lx\n", size_needed);
            return NULL;
        }
        to_user = (con_touser*)kmalloc(size_needed, GFP_KERNEL);
        to_user->total_size = size_needed;
        for(int i=0; i<PROTOCOL_SUPPORTED; i++){
            to_user->con_count[i] = con_count[i];
            to_user->cons[i] = (void*)((size_t)PTR(arg) + off[i]);
            extract_connections((void*)((size_t)to_user + off[i]), i, con_count[i]);
        }
    }else{
        unsigned off = sizeof(con_touser);
        size_t size_needed = off + TO_USER_SIZE(proto) * con_count[proto];
        if(size_needed > MAX_CON_BUFLEN(proto)){
            printk(KERN_ERR "Copy size abnormal, there may be a bug in this kernel module! size: %lx\n", size_needed);
            to_user->total_size = 0;
            return to_user;
        }
        to_user = (con_touser*)kmalloc(size_needed, GFP_KERNEL);
        to_user->total_size = size_needed;
        for(int i=0; i<PROTOCOL_SUPPORTED; i++){
            to_user->con_count[i] = 0;
            to_user->cons[i] = NULL;
        }
        to_user->con_count[proto] = con_count[proto];
        to_user->cons[proto] = (void*)((size_t)PTR(arg) + off);
        extract_connections((void*)((size_t)to_user + off), proto, con_count[proto]);
    }
    spin_unlock(&con_lock);  // but the lock is necessary
    return to_user;
}

log_touser* get_logs(unsigned long arg){
    spin_lock(&log_lock);
    unsigned proto = LSB(arg);
    size_t addr = PTR(arg);
    log_touser* to_user;
    if(proto == RULE_ALL){
        unsigned off[PROTOCOL_SUPPORTED] = {sizeof(log_touser)};
        off[1] = off[0] + sizeof(tcp_log) * log_cnt[RULE_TCP];
        off[2] = off[1] + sizeof(udp_log) * log_cnt[RULE_UDP];
        size_t size_needed = off[2] + sizeof(icmp_log) * log_cnt[RULE_ICMP];
        to_user = (log_touser*)kmalloc(size_needed, GFP_KERNEL);
        to_user->total_size = size_needed;
        for(int i=0; i<PROTOCOL_SUPPORTED; i++){
            to_user->log_count[i] = log_cnt[i];
            to_user->logs[i] = (void*)(addr + off[i]);
            extract_logs((void*)((size_t)to_user + off[i]), i, log_cnt[i]);
        }
    }else{
        unsigned off = sizeof(log_touser);
        size_t size_needed = off + LOG_SIZE(proto) * log_cnt[proto];
        to_user = (log_touser*)kmalloc(size_needed, GFP_KERNEL);
        to_user->total_size = size_needed;
        for(int i=0; i<PROTOCOL_SUPPORTED; i++){
            to_user->log_count[i] = 0;
            to_user->logs[i] = NULL;
        }
        to_user->log_count[proto] = log_cnt[proto];
        to_user->logs[proto] = (void*)(addr + off);
        extract_logs((void*)((size_t)to_user + off), proto, log_cnt[proto]);
    }
    spin_unlock(&log_lock);
    return to_user;
}

log_touser* get_new_logs(unsigned long arg){
    spin_lock(&log_lock);
    unsigned proto = LSB(arg);
    size_t addr = PTR(arg);
    log_touser* to_user;
    if(proto == RULE_ALL){
        unsigned off[PROTOCOL_SUPPORTED] = {sizeof(log_touser)};
        off[1] = off[0] + sizeof(tcp_log) * new_log_cnt[RULE_TCP];
        off[2] = off[1] + sizeof(udp_log) * new_log_cnt[RULE_UDP];
        size_t size_needed = off[2] + sizeof(icmp_log) * new_log_cnt[RULE_ICMP];
        to_user = (log_touser*)kmalloc(size_needed, GFP_KERNEL);
        to_user->total_size = size_needed;
        for(int i=0; i<PROTOCOL_SUPPORTED; i++){
            to_user->log_count[i] = new_log_cnt[i];
            to_user->logs[i] = (void*)(addr + off[i]);
            extract_new_logs((void*)((size_t)to_user + off[i]), i, new_log_cnt[i]);
        }
    }else{
        unsigned off = sizeof(log_touser);
        size_t size_needed = off + LOG_SIZE(proto) * new_log_cnt[proto];
        to_user = (log_touser*)kmalloc(size_needed, GFP_KERNEL);
        to_user->total_size = size_needed;
        for(int i=0; i<PROTOCOL_SUPPORTED; i++){
            to_user->log_count[i] = 0;
            to_user->logs[i] = NULL;
        }
        to_user->log_count[proto] = new_log_cnt[proto];
        to_user->logs[proto] = (void*)(addr + off);
        extract_new_logs((void*)((size_t)to_user + off), proto, new_log_cnt[proto]);
    }
    spin_unlock(&log_lock);
    return to_user;
}

int write_file(const char* filename, const char* buf, size_t len, bool trunc){
    struct file* file;
    if(trunc) {
        file = filp_open(filename, O_WRONLY | O_TRUNC | O_CREAT, 0666);
        if (IS_ERR(file)) {
            printk(KERN_ERR
            "Failed to open file %s: %ld\n", filename, PTR_ERR(file));
            return -1;
        }
    }
    else{
        file = filp_open(filename, O_RDWR | O_CREAT, 0666);
        if(IS_ERR(file)){
            printk(KERN_ERR "Failed to open file %s: %ld\n", filename, PTR_ERR(file));
            return -1;
        }
        loff_t offset = vfs_llseek(file, offset, SEEK_END);
        if(offset < 0){
            printk(KERN_ERR "Failed to seek to the end of %s", filename);
            return -1;
        }
    }
//    if (!file->f_op || !file->f_op->write) {
//        pr_err("Invalid file handle for %s\n", filename);
//        return -1;
//    }
    if(!buf){
        filp_close(file, NULL);
        return 0;
    }
    ssize_t ret = kernel_write(file, buf, len, &file->f_pos);
    if(ret < 0){
        printk(KERN_ERR "Failed to write to %s: %zd\n", filename, ret);
        filp_close(file, NULL);
        return -1;
    }else{
        printk(KERN_INFO "Data written to %s: %zd bytes\n", filename, ret);
        filp_close(file, NULL);
        return 0;
    }
}

int read_file(const char* filename, char* buf, size_t len){   // if len <= 0, read all content
    // WON'T CHECK the buffer length, attention to potential leak!!!
    struct file* file = filp_open(filename, O_RDONLY, 0);
    if(IS_ERR(file)){
        printk(KERN_ERR "Failed to open file %s: %ld\n", filename, PTR_ERR(file));
        return -1;
    }
    ssize_t ret = kernel_read(file, buf, len, &file->f_pos);
    if(ret < 0){
        printk(KERN_ERR "Failed to write: %zd\n", ret);
        filp_close(file, NULL);
        return -1;
    }else{
        printk(KERN_INFO "Data read from %s: %zd bytes\n", filename, ret);
        filp_close(file, NULL);
        return 0;
    }
}

long long file_size(const char* filename){
    struct file *file = filp_open(filename, O_RDONLY, 0);  // 文件描述符对应的 struct file 结构
    if(IS_ERR(file)){
        printk(KERN_ERR "Failed to open file %s for getting its size.", filename);
        return -1;
    }
    struct inode *inode = file_inode(file);
    long long size = i_size_read(inode);
    filp_close(file, NULL);
    return size;
}