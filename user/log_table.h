#ifndef LOG_TABLE_H
#define LOG_TABLE_H

#include <QHostAddress>
#include <QItemDelegate>

#include "common.h"

class log_table
{
public:
    log_table();
    static void update_log(unsigned proto);
    static QList<QString> analyse_kernel_info(tcp_log* log);
    static QList<QString> analyse_kernel_info(udp_log* log);
    static QList<QString> analyse_kernel_info(icmp_log* log);
};

#endif // LOG_TABLE_H
