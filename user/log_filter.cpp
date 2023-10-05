#include "log_filter.h"
#include "ui_log_filter.h"

log_filter::log_filter(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::log_filter)
{
    ui->setupUi(this);
    ui->choice_tcp->setChecked(true);
    ui->srcip_filter->setEnabled(false);
    ui->dstip_filter->setEnabled(false);
    ui->srcport_filter->setEnabled(false);
    ui->dstport_filter->setEnabled(false);
    ui->action_filter->setEnabled(false);
    ui->hp_filter->setEnabled(false);
    ui->start_time->setEnabled(false);
    ui->end_time->setEnabled(false);
    widget = new filter_widget();
    proto = RULE_TCP;
}

log_filter::~log_filter()
{
    delete widget;
    delete ui;
}

void log_filter::on_choice_tcp_clicked()
{
    ui->srcport->setEnabled(true);
    ui->srcport_filter->setEnabled(true);
    ui->dstport->setEnabled(true);
    ui->dstport_filter->setEnabled(true);
    proto = RULE_TCP;
}

void log_filter::on_choice_udp_clicked()
{
    ui->srcport->setEnabled(true);
    ui->srcport_filter->setEnabled(true);
    ui->dstport->setEnabled(true);
    ui->dstport_filter->setEnabled(true);
    proto = RULE_UDP;
}

void log_filter::on_choice_icmp_clicked()
{
    ui->srcport->setEnabled(false);
    ui->srcport_filter->setEnabled(false);
    ui->srcport_filter->clear();
    ui->dstport->setEnabled(false);
    ui->dstport_filter->setEnabled(false);
    ui->dstport_filter->clear();
    proto = RULE_ICMP;
}

void log_filter::on_srcip_stateChanged(int arg1)
{
    Q_UNUSED(arg1);
    if(!ui->srcip->isChecked()){
        ui->srcip_filter->setEnabled(false);
        ui->srcip_filter->clear();
    }else
        ui->srcip_filter->setEnabled(true);
    srcip_activated = ui->srcip->isChecked();
}

void log_filter::on_dstip_stateChanged(int arg1)
{
    Q_UNUSED(arg1);
    if(!ui->dstip->isChecked()){
        ui->dstip_filter->setEnabled(false);
        ui->dstip_filter->clear();
    }else
        ui->dstip_filter->setEnabled(true);
    dstip_activated = ui->dstip->isChecked();
}

void log_filter::on_srcport_stateChanged(int arg1)
{
    Q_UNUSED(arg1);
    if(!ui->srcport->isChecked()){
        ui->srcport_filter->setEnabled(false);
        ui->srcport_filter->clear();
    }else
        ui->srcport_filter->setEnabled(true);
    srcport_activated = ui->srcport->isChecked();
}

void log_filter::on_dstport_stateChanged(int arg1)
{
    Q_UNUSED(arg1);
    if(!ui->dstport->isChecked()){
        ui->dstport_filter->setEnabled(false);
        ui->dstport_filter->clear();
    }else
        ui->dstport_filter->setEnabled(true);
    dstport_activated = ui->dstport->isChecked();
}

void log_filter::on_action_stateChanged(int arg1)
{
    Q_UNUSED(arg1);
    if(!ui->action->isChecked()){
        ui->action_filter->setEnabled(false);
        ui->action_filter->clear();
    }else
        ui->action_filter->setEnabled(true);
    action_activated = ui->action->isChecked();
}

void log_filter::on_hp_stateChanged(int arg1)
{
    Q_UNUSED(arg1);
    if(!ui->hp->isChecked()){
        ui->hp_filter->setEnabled(false);
        ui->hp_filter->clear();
    }else
        ui->hp_filter->setEnabled(true);
    hp_activated = ui->hp->isChecked();
}

void log_filter::on_time_stateChanged(int arg1)
{
    Q_UNUSED(arg1);
    if(!ui->time->isChecked()){
        ui->start_time->setEnabled(false);
        ui->end_time->setEnabled(false);
    }else{
        ui->start_time->setEnabled(true);
        ui->end_time->setEnabled(true);
    }
    time_activated = ui->time->isChecked();
}

void log_filter::on_srcip_filter_editingFinished()
{
    QList<CIDR>* cidrs = analyse_cidr_str(ui->srcip_filter->text());
    if(!cidrs){
        QMessageBox::warning(this, "warning", "cidr input format error!");
        ui->srcip_filter->clear();
    }
    if(srcip)
        delete srcip;
    srcip = cidrs;
}

QList<CIDR>* log_filter::analyse_cidr_str(QString str){
    QList<QString> cidr_list = str.split(",");
    for(size_t i=0; i<cidr_list.length(); i++)
        cidr_list[i] = cidr_list[i].trimmed();
    QRegExp re("^([1]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([1]?\\d\\d?|2[0-4]\\d|25[0-5])"
               "\\.([1]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([1]?\\d\\d?|2[0-4]\\d|25[0-5])(/([1-2]?\\d|3[0-2]))?$");
    QList<CIDR>* ret = new QList<CIDR>();
    for(auto s: cidr_list){
        if(re.indexIn(s) == -1){
            delete ret;
            return NULL;
        }
    }
    for(auto s: cidr_list){
        QHostAddress ip;
        int mask;
        CIDR cidr;
        if(s.indexOf("/") >= 0){
            QList<QString> x = s.split("/");
            ip.setAddress(x[0]);
            cidr.mask = x[1].toInt();
        }else{
            ip.setAddress(s);
            cidr.mask = 32;
        }
        cidr.ip = ip.toIPv4Address();
        ret->append(cidr);
    }
    return ret;
}

QList<port_range>* log_filter::analyse_portrange_str(QString str){
    QStringList ranges = str.split(",");
    QList<port_range>* ret = new QList<port_range>();
    for(int i=0; i<ranges.length(); i++){
        QStringList numbers = ranges[i].split("~");
        if(numbers.size() == 1){
            bool ok;
            int number = numbers[0].toInt(&ok);
            if(!ok || number < 0 || number > 65535){
                delete ret;
                return NULL;
            }
            ret->append({number, number});
        }else if(numbers.size() == 2){
            bool ok1, ok2;
            int number1 = numbers[0].toInt(&ok1);
            int number2 = numbers[1].toInt(&ok2);
            if(!ok1 || !ok2 || number1 < 0 || number1 > 65536 || number2 < 0 ||
                    number2 > 65535 || number1 > number2){
                delete ret;
                return NULL;
            }
            ret->append({number1, number2});
        }else{
            delete ret;
            return NULL;
        }
    }
    return ret;
}

void log_filter::on_dstip_filter_editingFinished()
{
    QList<CIDR>* cidrs = analyse_cidr_str(ui->dstip_filter->text());
    if(!cidrs){
        QMessageBox::warning(this, "warning", "cidr input format error!");
        ui->dstip_filter->clear();
    }
    if(dstip)
        delete dstip;
    dstip = cidrs;
}

void log_filter::on_srcport_filter_editingFinished()
{
    QList<port_range>* ranges = analyse_portrange_str(ui->srcport_filter->text());
    if(!ranges){
        QMessageBox::warning(this, "warning", "port range input format error!");
        ui->srcport_filter->clear();
    }
    srcport = ranges;
}

void log_filter::on_dstport_filter_editingFinished()
{
    QList<port_range>* ranges = analyse_portrange_str(ui->dstport_filter->text());
    if(!ranges){
        QMessageBox::warning(this, "warning", "port range input format error!");
        ui->dstport_filter->clear();
    }
    dstport = ranges;
}

void log_filter::on_action_filter_currentIndexChanged(int index)
{
    action = index;
}

void log_filter::on_hp_filter_currentIndexChanged(int index)
{
    hp = index;
}

void log_filter::on_start_time_editingFinished()
{
    start_time = ui->start_time->dateTime();
}

void log_filter::on_end_time_editingFinished()
{
    end_time = ui->end_time->dateTime();
}

void log_filter::on_btn_clear_filter_clicked()
{
    ui->srcip->setChecked(false);
    ui->dstip->setChecked(false);
    ui->srcport->setChecked(false);
    ui->dstport->setChecked(false);
    ui->action->setChecked(false);
    ui->hp->setChecked(false);
    ui->time->setChecked(false);
    filter_activated = false;
}

void log_filter::on_btn_activate_clicked()
{
    if(!(ui->srcip->isChecked() ||
         ui->dstip->isChecked() ||
         ui->srcport->isChecked() ||
         ui->dstport->isChecked() ||
         ui->action->isChecked() ||
         ui->hp->isChecked() ||
         ui->time->isChecked())){
        QMessageBox::warning(this, "warning", "No filter specified, you cannot activate filter!");
        return;
    }
    filter_activated = true;
    do_filter();
}

bool log_filter::is_inCIDR(unsigned int ip, QList<CIDR>* cidrs){
    for(auto cidr: *cidrs){
        if(cidr.mask == 0)
            return true;
        if(cidr.mask == 32 && ip == cidr.ip)
            return true;
        if(!((ip ^ cidr.ip) & (0xFFFFFFFF << (32 - cidr.mask))))
            return true;
    }
    return false;
}

bool log_filter::is_inCIDR(QString ip, QList<CIDR>* cidrs){
    QHostAddress ha(ip);
    return is_inCIDR(ha.toIPv4Address(), cidrs);
}

bool log_filter::is_inrange(unsigned short port, QList<port_range>* ranges){
    int i = 0;
    for(; i<ranges->length(); i++)
        if(port >= (*ranges)[i].start && port <= (*ranges)[i].end)
            return true;
    return false;
}

bool log_filter::ipport_inrange(QString str, QList<CIDR>* cidrs, QList<port_range>* ranges){
    QRegExp re("^([1]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([1]?\\d\\d?|2[0-4]\\d|25[0-5])"
               "\\.([1]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([1]?\\d\\d?|2[0-4]\\d|25[0-5]):(\\d+)$");
    if(re.indexIn(str) < 0)
        return false;
    QList<QString> ip_port = str.split(":");
    if(ip_port.length() != 2)
        return false;
    int port = ip_port[1].toInt();
    if(port < 0 || port >= 65536)
        return false;
    return is_inCIDR(ip_port[0], cidrs) && is_inrange(port, ranges);
}

bool log_filter::match(QList<QStandardItem*> log, unsigned proto){
    switch(proto){
    case RULE_TCP:
    case RULE_UDP:{
        QList<QString> src = log[1]->text().split(":");
        if(srcip_activated && srcip && !is_inCIDR(src[0], srcip))
            return false;
        if(srcport_activated && srcport && !is_inrange(src[1].toInt(), srcport))
            return false;
        QList<QString> dst = log[2]->text().split(":");
        if(dstip_activated && dstip && !is_inCIDR(dst[0], dstip))
            return false;
        if(dstport_activated && dstport && !is_inrange(dst[1].toInt(), dstport))
            return false;
        if(action_activated && QString::compare(log[3]->text(), ui->action_filter->currentText(), Qt::CaseInsensitive))
            return false;
        if(hp_activated && QString::compare(log[4]->text(), ui->hp_filter->currentText(), Qt::CaseInsensitive))
            return false;
        if(time_activated){
            if(ui->start_time->dateTime() > QDateTime::fromString(log[0]->text(), "yyyy-MM-dd hh:mm:ss.zzz"))
                return false;
            if(ui->end_time->dateTime() < QDateTime::fromString(log[0]->text(), "yyyy-MM-dd hh:mm:ss.zzz"))
                return false;
        }
        return true;
    }
    case RULE_ICMP:{
        if(srcip_activated && srcip && !is_inCIDR(log[1]->text(), srcip))
            return false;
        if(dstip_activated && srcport && !is_inCIDR(log[2]->text(), dstip))
            return false;
        if(action_activated && log[5]->text() != ui->action_filter->currentText())
            return false;
        if(hp_activated && log[6]->text() != ui->hp_filter->currentText())
            return false;
        if(time_activated){
            if(ui->start_time->dateTime() > QDateTime::fromString(log[0]->text(), "yyyy-MM-dd hh:mm:ss.zzz"))
                return false;
            if(ui->end_time->dateTime() < QDateTime::fromString(log[0]->text(), "yyyy-MM-dd hh:mm:ss.zzz"))
                return false;
        }
        return true;
    }
    default:
        return false;
    }
}

QStandardItemModel* log_filter::deep_copy(unsigned proto){
    QStandardItemModel* src = log_models[proto];
    QStandardItemModel* cloned = new QStandardItemModel(src->rowCount(), src->columnCount());
    if(src->rowCount() == log_length[proto]){
        for(int i=log_model_ptr[proto]; i<log_length[proto]; i++){
            for(int j=0; j<src->columnCount(); j++){
                QStandardItem* cloned_item = log_models[proto]->item(i, j)->clone();
                cloned->setItem(i - log_model_ptr[proto], j, cloned_item);
            }
        }
        for(int i=0; i<log_model_ptr[proto]; i++){
            for(int j=0; j<src->columnCount(); j++){
                QStandardItem* cloned_item = log_models[proto]->item(i, j)->clone();
                cloned->setItem(i + log_length[proto] - log_model_ptr[proto], j, cloned_item);
            }
        }
    }else{
        for(int i=0; i<log_model_ptr[proto]; i++){
            for(int j=0; j<src->columnCount(); j++){
                QStandardItem* cloned_item = log_models[proto]->item(i, j)->clone();
                cloned->setItem(i, j, cloned_item);
            }
        }
    }
    return cloned;
}

void log_filter::do_filter(){
    filter_model.clear();
    if(log_models[proto]->rowCount() == 0){
        QMessageBox::information(this, "note", "There is no log here yet.");
        return;
    }
    QStandardItemModel* target = deep_copy(proto);
    int limit = target->rowCount();
    for(int i=0; i<limit; i++){
        QList<QStandardItem*> target_row = target->takeRow(0);
        if(match(target_row, proto))
            filter_model.appendRow(target_row);
    }
    filter_model.setColumnCount(log_headers[proto].length());
    for(int i=0; i<log_headers[proto].length(); i++)
        filter_model.setHeaderData(i, Qt::Horizontal, log_headers[proto][i]);
    widget->initialize_table(&filter_model);
    widget->show();
}
