#include "rule_table.h"

rule_table::rule_table()
{

}

void rule_table::update_rules(unsigned hook, unsigned proto){
    size_t size_needed = MAX_RULE_BUFLEN;
    rule_ifh* data = (rule_ifh*)malloc(size_needed);
    int ioctl_ret = ioctl(devfd, IOCTL_GET_RULE | hook | IOCTL_PROTO(proto), data);
    if(ioctl_ret){
        QMessageBox::critical(nullptr, "error", "Error occurred while getting rules from kernel.");
        return;
    }
    fwrule_user* rules = (fwrule_user*)(data + 1);
    rule_models[hook][proto]->removeRows(0, rule_models[hook][proto]->rowCount());
    for(unsigned i=0; i<data->rule_num; i++)
        rule_models[hook][proto]->appendRow(analyse_kernel_info(rules + i));
    free(data);
}

QList<QStandardItem*> rule_table::analyse_kernel_info(fwrule_user* from_kernel){
    QList<QStandardItem*> ret;
    switch(from_kernel->protocol){
    case RULE_TCP:
    case RULE_UDP:{
        // Sender IP, Sender Port, Receiver IP, Receiver Port, Protocol, Action
        QHostAddress ipaddr(from_kernel->src_ip.ip);
        ret << new QStandardItem(ipaddr.toString() + "/" + QString::number(from_kernel->src_ip.mask));
        ret << new QStandardItem(range_to_string(from_kernel->src_ports, from_kernel->src_port_len));
        ipaddr.setAddress(from_kernel->dst_ip.ip);
        ret << new QStandardItem(ipaddr.toString() + "/" + QString::number(from_kernel->dst_ip.mask));
        ret << new QStandardItem(range_to_string(from_kernel->dst_ports, from_kernel->dst_port_len));
        ret << new QStandardItem(from_kernel->protocol == RULE_TCP ? "TCP" : "UDP");
        ret << new QStandardItem(from_kernel->action & 1 ? "ACCEPT" : "REJECT");
        ret << new QStandardItem(from_kernel->action & 2 ? "LOG" : "NO LOG");
        break;
    }
    case RULE_ICMP:{
        // Sender IP, Receiver IP, Protocol, Action
        QHostAddress ipaddr(from_kernel->src_ip.ip);
        ret << new QStandardItem(ipaddr.toString() + "/" + QString::number(from_kernel->src_ip.mask));
        ipaddr.setAddress(from_kernel->dst_ip.ip);
        ret << new QStandardItem(ipaddr.toString() + "/" + QString::number(from_kernel->dst_ip.mask));
        ret << new QStandardItem("ICMP");
        ret << new QStandardItem(from_kernel->action & 1 ? "ACCEPT" : "REJECT");
        ret << new QStandardItem(from_kernel->action & 2 ? "LOG" : "NO LOG");
        break;
    }
    }
    if(from_kernel->timeout)
        ret << new QStandardItem(sectime_tostring(from_kernel->timeout));
    else
        ret << new QStandardItem("/");
    for(QStandardItem* item : ret)
        item->setData(Qt::AlignCenter, Qt::TextAlignmentRole);
    return ret;
}

QString rule_table::range_to_string(port_range* range, unsigned len){
    QStringList ret = {};
    for(unsigned i=0; i<len; i++){
        if(range[i].start == range[i].end)
            ret << QString::number(range[i].start);
        else
            ret << QString::number(range[i].start) + "~" + QString::number(range[i].end);
    }
    return ret.join(", ");
}

bool rule_table::add_rule(rule_tbi* user){
    return !ioctl(devfd, IOCTL_ADD_RULE, user);
}
