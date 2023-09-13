#ifndef CON_TABLE_H
#define CON_TABLE_H

#include <QDebug>
#include <string>
#include <fcntl.h>
#include <QString>
#include <unistd.h>
#include <sys/ioctl.h>
#include <QHostAddress>
#include <QStandardItemModel>

#include "common.h"

#define TCP_CON_UNDEFINED   0
#define TCP_CON_SYN 		1
#define TCP_CON_SYNACK 		2
#define TCP_CON_ACK			3
#define TCP_CON_CONNECTED	3
#define TCP_CON_FIN_1		4
#define TCP_CON_ACK_1		5
#define TCP_CON_FIN_2		6
#define TCP_CON_ACK_2		7
#define TCP_CON_CLOSED		7

const QString tcp_status[8] = {
    "undefined", "client syn", "server synack", "connected",
    "first fin", "first finack", "second fin", "closed"
};

class con_table
{
public:
    con_table();

    static void update_connections(unsigned);
    static QList<QStandardItem*> analyse_kernel_info(void*, unsigned);

};

#endif // CON_TABLE_H
