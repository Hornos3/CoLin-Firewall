#ifndef RULE_TABLE_H
#define RULE_TABLE_H

#include <QObject>
#include <unistd.h>
#include <sys/ioctl.h>
#include <QHostAddress>
#include <QStandardItemModel>

#include "common.h"
#include "rule_adder.h"

class rule_table
{
public:
    rule_table();

    static void update_rules(unsigned, unsigned);
    static QList<QStandardItem*> analyse_kernel_info(fwrule_user*);
    static QString range_to_string(port_range*, unsigned);
    static bool add_rule(rule_tbi*);
};

#endif // RULE_TABLE_H
