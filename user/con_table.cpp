#include "con_table.h"

con_table::con_table()
{

}

void con_table::update_connections(unsigned proto){
    size_t size_needed = MAX_CON_BUFLEN(proto);
    con_touser* data = (con_touser*)malloc(size_needed);
    int ioctl_ret = ioctl(devfd, IOCTL_GET_CON, (size_t)data ^ proto);
    if(ioctl_ret){
        QMessageBox::critical(nullptr, "error", "Error occurred while getting connection infos from kernel.");
        return;
    }
    tu_con_touser* connections = (tu_con_touser*)data->cons[proto];
    unsigned length = data->con_count[proto];
    connection_models[proto]->removeRows(0, connection_models[proto]->rowCount());
    for(unsigned i=0; i<length; i++)
        connection_models[proto]->appendRow(
                    analyse_kernel_info(connections + i, proto));
    free(data);
}

QList<QStandardItem*> con_table::analyse_kernel_info(void* from_kernel, unsigned proto){
    QList<QStandardItem*> ret;
    switch(proto){
    case RULE_TCP:
    case RULE_UDP:{
        // client, server, status(for tcp)
        tu_con_touser* data = (tu_con_touser*)from_kernel;
        QHostAddress ipaddr(data->header.cliip);
        ret << new QStandardItem(SPACE(ipaddr.toString() + ":" +
                                 QString::fromStdString(std::to_string(data->header.cliport))));
        ipaddr.setAddress(data->header.srvip);
        ret << new QStandardItem(SPACE(ipaddr.toString() + ":" +
                                 QString::fromStdString(std::to_string(data->header.srvport))));
        ret << new QStandardItem(usectime_tostring(data->last));
        ret << new QStandardItem(sectime_tostring(data->timeout));
        break;
    }
    case RULE_ICMP:{
        icmp_con_touser* data = (icmp_con_touser*)from_kernel;
        QHostAddress ipaddr(data->header.cliip);
        ret << new QStandardItem(SPACE(ipaddr.toString()));
        ipaddr.setAddress(data->header.srvip);
        ret << new QStandardItem(SPACE(ipaddr.toString()));
        ret << new QStandardItem(SPACE(QString::number(data->type)));
        ret << new QStandardItem(usectime_tostring(data->last));
        ret << new QStandardItem(sectime_tostring(data->timeout));
        break;
    }
    }
    for(QStandardItem* item : ret)
        item->setData(Qt::AlignCenter, Qt::TextAlignmentRole);
    return ret;
}
