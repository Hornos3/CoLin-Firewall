#include "nat_table.h"

nat_table::nat_table()
{

}

void nat_table::update_nat(){
    nat_config_touser* data = (nat_config_touser*)malloc(MAX_NAT_BUFLEN);
    unsigned cnt = ioctl(devfd, IOCTL_GET_PAT, data);
    if(!cnt)
        return;
    nat_model->removeRows(0, nat_model->rowCount());
    for(int i=0; i<cnt; i++){
        /////////////////////////////
        if(data[i].NAT_mode != NAT_PAT)
            continue;
        /////////////////////////////
        QList<QStandardItem*> next_row;
        QHostAddress ip(data[i].config.pc.lan.ip);
        next_row << new QStandardItem(SPACE(ip.toString() + "/" + QString::number(data[i].config.pc.lan.mask)));
        ip.setAddress(data[i].config.pc.wan);
        next_row << new QStandardItem(SPACE(ip.toString()));
        for(QStandardItem* item : next_row)
            item->setData(Qt::AlignCenter, Qt::TextAlignmentRole);
        nat_model->appendRow(next_row);
    }
    free(data);
}
