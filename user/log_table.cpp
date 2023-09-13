#include "log_table.h"

log_table::log_table()
{

}

void log_table::update_log(unsigned proto){
    log_touser* data = (log_touser*)malloc(MAX_LOG_BUFLEN(proto));
    if(ioctl(devfd, IOCTL_GET_NEW_LOG, (size_t)data ^ proto)){
        QMessageBox::critical(nullptr, "error", "Failed to get logs from kernel.");
        return;
    }
    switch(proto){
    case RULE_TCP:{
        for(unsigned i=0; i<data->log_count[RULE_TCP]; i++){
            QList<QStandardItem*> sheet =
                 analyse_kernel_info((tcp_log*)data->logs[RULE_TCP] + i);
            log_models[proto]->appendRow(sheet);
        }
        break;
    }
    case RULE_UDP:{
        for(unsigned i=0; i<data->log_count[RULE_UDP]; i++){
            QList<QStandardItem*> sheet =
                 analyse_kernel_info((udp_log*)data->logs[RULE_UDP] + i);
            log_models[proto]->appendRow(sheet);
        }
        break;
    }
    case RULE_ICMP:{
        for(unsigned i=0; i<data->log_count[RULE_ICMP]; i++){
            QList<QStandardItem*> sheet =
                 analyse_kernel_info((icmp_log*)data->logs[RULE_ICMP] + i);
            log_models[proto]->appendRow(sheet);
        }
        break;
    }
    }
    // delete previous lines
    if((unsigned)log_models[proto]->rowCount() > log_length[proto]){
        log_models[proto]->removeRows(0,
            log_models[proto]->rowCount() - log_length[proto]);
    }
}

QList<QStandardItem*> log_table::analyse_kernel_info(tcp_log* log){
    QList<QStandardItem*> ret;
    ret << new QStandardItem(usectime_tostring(log->timestamp));
    QHostAddress ipaddr(log->srcip);
    ret << new QStandardItem(SPACE(ipaddr.toString()
        + ":" + QString::number(log->sport)));
    ipaddr.setAddress(log->dstip);
    ret << new QStandardItem(SPACE(ipaddr.toString()
        + ":" + QString::number(log->dport)));
    if(log->action)
        ret << new QStandardItem(SPACE("ACCEPT"));
    else
        ret << new QStandardItem(SPACE("REJECT"));
    ret << new QStandardItem(SPACE(QString::number(log->seq)));
    ret << new QStandardItem(SPACE(QString::number(log->ack_seq)));
    QStringList symbols;
    if(log->fin)
        symbols << "FIN";
    if(log->syn)
        symbols << "SYN";
    if(log->rst)
        symbols << "RST";
    if(log->psh)
        symbols << "PSH";
    if(log->ack)
        symbols << "ACK";
    if(log->urg)
        symbols << "URG";
    if(log->ece)
        symbols << "ECE";
    if(log->cwr)
        symbols << "CWR";
    ret << new QStandardItem(SPACE(symbols.join(", ")));
    ret << new QStandardItem(SPACE(QString::number(log->length)));
    for(QStandardItem* item : ret)
        item->setData(Qt::AlignCenter, Qt::TextAlignmentRole);
    return ret;
}

QList<QStandardItem*> log_table::analyse_kernel_info(udp_log* log){
    QList<QStandardItem*> ret;
    ret << new QStandardItem(usectime_tostring(log->timestamp));
    QHostAddress ipaddr(log->srcip);
    ret << new QStandardItem(SPACE(ipaddr.toString()
        + ":" + QString::number(log->sport)));
    ipaddr.setAddress(log->dstip);
    ret << new QStandardItem(SPACE(ipaddr.toString()
        + ":" + QString::number(log->dport)));
    if(log->action)
        ret << new QStandardItem(SPACE("ACCEPT"));
    else
        ret << new QStandardItem(SPACE("REJECT"));
    ret << new QStandardItem(SPACE(QString::number(log->length)));
    for(QStandardItem* item : ret)
        item->setData(Qt::AlignCenter, Qt::TextAlignmentRole);
    return ret;
}

QList<QStandardItem*> log_table::analyse_kernel_info(icmp_log* log){
    QList<QStandardItem*> ret;
    ret << new QStandardItem(usectime_tostring(log->timestamp));
    QHostAddress ipaddr(log->srcip);
    ret << new QStandardItem(SPACE(ipaddr.toString()));
    ipaddr.setAddress(log->dstip);
    ret << new QStandardItem(SPACE(ipaddr.toString()));
    ret << new QStandardItem(SPACE(QString::number(log->type)));
    ret << new QStandardItem(SPACE(QString::number(log->code)));
    if(log->action)
        ret << new QStandardItem(SPACE("ACCEPT"));
    else
        ret << new QStandardItem(SPACE("REJECT"));
    ret << new QStandardItem(SPACE(QString::number(log->length)));
    for(QStandardItem* item : ret)
        item->setData(Qt::AlignCenter, Qt::TextAlignmentRole);
    return ret;
}
