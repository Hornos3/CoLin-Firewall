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
    QList<QList<QString>> temp;
    switch(proto){
    case RULE_TCP:{
        for(unsigned i=0; i<data->log_count[RULE_TCP]; i++)
            temp.append(analyse_kernel_info((tcp_log*)data->logs[RULE_TCP] + i));
        break;
    }
    case RULE_UDP:{
        for(unsigned i=0; i<data->log_count[RULE_UDP]; i++)
            temp.append(analyse_kernel_info((udp_log*)data->logs[RULE_UDP] + i));
        break;
    }
    case RULE_ICMP:{
        for(unsigned i=0; i<data->log_count[RULE_ICMP]; i++)
            temp.append(analyse_kernel_info((icmp_log*)data->logs[RULE_ICMP] + i));
        break;
    }
    }
    if(temp.length() == 0)
        return;
    int rowCount = log_models[proto]->rowCount();
    if(rowCount == log_length[proto]){
        for(int i=0; i<temp.length(); i++){
            for(int j=0; j<log_models[proto]->columnCount(); j++){
                log_models[proto]->setData(log_models[proto]->index(log_model_ptr[proto], j), temp[i][j]);
                log_models[proto]->item(i, j)->setTextAlignment(Qt::AlignCenter);
            }
            ++log_model_ptr[proto];
            if(log_model_ptr[proto] >= log_length[proto])
                log_model_ptr[proto] %= log_length[proto];
        }
    }else if(rowCount + temp.length() > log_length[proto]){      // This insertion will exceed the row limit
        log_models[proto]->insertRows(rowCount, log_length[proto] - rowCount);
        for(int i=0; i<temp.length(); i++){
            for(int j=0; j<log_models[proto]->columnCount(); j++){
                log_models[proto]->setData(log_models[proto]->index(log_model_ptr[proto], j), temp[i][j]);
                log_models[proto]->item(i, j)->setTextAlignment(Qt::AlignCenter);
            }
            ++log_model_ptr[proto];
            if(log_model_ptr[proto] >= log_length[proto])
                log_model_ptr[proto] %= log_length[proto];
        }
    }else{
        log_models[proto]->insertRows(log_models[proto]->rowCount(), temp.length());
        for(int i=rowCount; i<log_models[proto]->rowCount(); i++){
            for(int j=0; j<log_models[proto]->columnCount(); j++){
                log_models[proto]->setData(log_models[proto]->index(i, j), temp.at(i-rowCount).at(j));
                log_models[proto]->item(i, j)->setTextAlignment(Qt::AlignCenter);
            }
        }
        log_model_ptr[proto] = log_models[proto]->rowCount() % log_length[proto];
    }
}

QList<QString> log_table::analyse_kernel_info(tcp_log* log){
    QList<QString> ret;
    ret << usectime_tostring(log->timestamp);
    QHostAddress ipaddr(log->srcip);
    ret << SPACE(ipaddr.toString() + ":" + QString::number(log->sport));
    ipaddr.setAddress(log->dstip);
    ret << SPACE(ipaddr.toString() + ":" + QString::number(log->dport));
    if(log->action)
        ret << SPACE("ACCEPT");
    else
        ret << SPACE("REJECT");
    ret << SPACE(QString::number(log->seq));
    ret << SPACE(QString::number(log->ack_seq));
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
    ret << SPACE(symbols.join(", "));
    ret << SPACE(QString::number(log->length));
    return ret;
}

QList<QString> log_table::analyse_kernel_info(udp_log* log){
    QList<QString> ret;
    ret << usectime_tostring(log->timestamp);
    QHostAddress ipaddr(log->srcip);
    ret << SPACE(ipaddr.toString() + ":" + QString::number(log->sport));
    ipaddr.setAddress(log->dstip);
    ret << SPACE(ipaddr.toString() + ":" + QString::number(log->dport));
    if(log->action)
        ret << SPACE("ACCEPT");
    else
        ret << SPACE("REJECT");
    ret << SPACE(QString::number(log->length));
    return ret;
}

QList<QString> log_table::analyse_kernel_info(icmp_log* log){
    QList<QString> ret;
    ret << usectime_tostring(log->timestamp);
    QHostAddress ipaddr(log->srcip);
    ret << SPACE(ipaddr.toString());
    ipaddr.setAddress(log->dstip);
    ret << SPACE(ipaddr.toString());
    ret << SPACE(QString::number(log->type));
    ret << SPACE(QString::number(log->code));
    if(log->action)
        ret << SPACE("ACCEPT");
    else
        ret << SPACE("REJECT");
    ret << SPACE(QString::number(log->length));
    return ret;
}
