#ifndef NAT_TABLE_H
#define NAT_TABLE_H

#include <QHostAddress>

#include "common.h"

class nat_table
{
public:
    nat_table();
    static void update_nat();
};

#endif // NAT_TABLE_H
