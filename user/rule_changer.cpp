#include "rule_changer.h"
#include "ui_rule_changer.h"

rule_changer::rule_changer(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::rule_changer)
{
    ui->setupUi(this);
    QIntValidator* validator_255 = new QIntValidator(1, 256, this);
    ui->position->setValidator(validator_255);
    ui->srcip_0->setValidator(validator_255);
    ui->srcip_1->setValidator(validator_255);
    ui->srcip_2->setValidator(validator_255);
    ui->srcip_3->setValidator(validator_255);
    ui->dstip_0->setValidator(validator_255);
    ui->dstip_1->setValidator(validator_255);
    ui->dstip_2->setValidator(validator_255);
    ui->dstip_3->setValidator(validator_255);
    QIntValidator* validator_32 = new QIntValidator(0, 32, this);
    ui->srcip_mask->setValidator(validator_32);
    ui->dstip_mask->setValidator(validator_32);
    activate_choices(false);
}

rule_changer::~rule_changer()
{
    delete ui;
}

void rule_changer::activate_choices(bool activate){
    ui->srcip_0->setEnabled(activate);
    ui->srcip_1->setEnabled(activate);
    ui->srcip_2->setEnabled(activate);
    ui->srcip_3->setEnabled(activate);
    ui->srcip_mask->setEnabled(activate);
    ui->dstip_0->setEnabled(activate);
    ui->dstip_1->setEnabled(activate);
    ui->dstip_2->setEnabled(activate);
    ui->dstip_3->setEnabled(activate);
    ui->dstip_mask->setEnabled(activate);
    ui->srcports->setEnabled(activate && ui->proto->currentIndex() < 2);
    ui->dstports->setEnabled(activate && ui->proto->currentIndex() < 2);
    ui->action->setEnabled(activate);
    ui->log->setEnabled(activate);
    ui->timeout_isset->setEnabled(activate);
}

void rule_changer::fill_choices(){
    QStandardItemModel* model = rule_models[ui->hook->currentIndex()][ui->proto->currentIndex()];
    int idx = ui->position->text().toInt() - 1;
    if(idx >= model->rowCount() || idx < 0)
        return;
    CIDR src, dst;
    src = log_filter::analyse_cidr_str(model->item(idx, 0)->text())->at(0);
    switch(ui->proto->currentIndex()){
    case RULE_TCP:
    case RULE_UDP:{
        dst = log_filter::analyse_cidr_str(model->item(idx, 2)->text())->at(0);
        ui->srcports->setText(model->item(idx, 1)->text());
        ui->dstports->setText(model->item(idx, 3)->text());
        ui->action->setCurrentIndex(model->item(idx, 5)->text() == "ACCEPT");
        ui->log->setCurrentIndex(model->item(idx, 6)->text() == "LOG");
        if(model->item(idx, 7)->text() == "/")
            ui->timeout_isset->setChecked(false);
        else{
            ui->timeout_isset->setChecked(true);
            ui->timeout->setDateTime(QDateTime::fromString(model->item(idx, 7)->text(), "yyyy/M/d hh:mm:ss"));
        }
        break;
    }
    case RULE_ICMP:{
        dst = log_filter::analyse_cidr_str(model->item(idx, 1)->text())->at(0);
        ui->action->setCurrentIndex(model->item(idx, 3)->text() == "ACCEPT");
        ui->log->setCurrentIndex(model->item(idx, 4)->text() == "LOG");
        if(model->item(idx, 7)->text() == "/")
            ui->timeout_isset->setChecked(false);
        else{
            ui->timeout_isset->setChecked(true);
            ui->timeout->setDateTime(QDateTime::fromString(model->item(idx, 5)->text(), "yyyy/M/d hh:mm:ss"));
        }
        break;
    }
    }
    ui->srcip_0->setText(QString::number(src.ip >> 24));
    ui->srcip_1->setText(QString::number((src.ip >> 16) & 0xFF));
    ui->srcip_2->setText(QString::number((src.ip >> 8) & 0xFF));
    ui->srcip_3->setText(QString::number(src.ip & 0xFF));
    ui->srcip_mask->setText(QString::number(src.mask));
    ui->dstip_0->setText(QString::number(dst.ip >> 24));
    ui->dstip_1->setText(QString::number((dst.ip >> 16) & 0xFF));
    ui->dstip_2->setText(QString::number((dst.ip >> 8) & 0xFF));
    ui->dstip_3->setText(QString::number(dst.ip & 0xFF));
    ui->dstip_mask->setText(QString::number(dst.mask));
}

void rule_changer::update_tbi(){
    size_t size_needed = MAX_RULE_BUFLEN;
    rule_ifh* data = (rule_ifh*)malloc(size_needed);
    int ioctl_ret = ioctl(devfd, IOCTL_GET_RULE | ui->hook->currentIndex() | IOCTL_PROTO(ui->proto->currentIndex()), data);
    if(ioctl_ret){
        QMessageBox::critical(nullptr, "error", "Error occurred while getting rules from kernel.");
        return;
    }
    int idx = ui->position->text().toInt()-1;
    if(idx >= data->rule_num || idx < 0){
        free(data);
        return;
    }
    fwrule_user* rules = (fwrule_user*)(data + 1);
    memcpy(&(tbi.rule), rules, sizeof(fwrule_user));
}

void rule_changer::on_position_editingFinished()
{
    if(ui->position->text().isEmpty()){
        activate_choices(false);
        return;
    }
    if(ui->position->text().toInt() > rule_models[ui->hook->currentIndex()][ui->proto->currentIndex()]->rowCount() ||
            ui->position->text().toInt() <= 0){
        QMessageBox::warning(this, "warning", "rule index out of bound!");
        ui->position->setText("");
        activate_choices(false);
        return;
    }
    activate_choices(true);
    fill_choices();
    update_tbi();
}

void rule_changer::on_timeout_isset_stateChanged(int arg1)
{
    Q_UNUSED(arg1);
    ui->timeout->setEnabled(ui->timeout_isset->isChecked());
    if(!ui->timeout_isset->isChecked()){
        tbi.rule.timeout = 0;
    }
}

void rule_changer::on_srcip_0_editingFinished(){tbi.rule.src_ip.ip = tbi.rule.src_ip.ip & 0x00FFFFFF + ui->srcip_0->text().toInt() << 24;}
void rule_changer::on_srcip_1_editingFinished(){tbi.rule.src_ip.ip = tbi.rule.src_ip.ip & 0xFF00FFFF + ui->srcip_1->text().toInt() << 16;}
void rule_changer::on_srcip_2_editingFinished(){tbi.rule.src_ip.ip = tbi.rule.src_ip.ip & 0xFFFF00FF + ui->srcip_2->text().toInt() << 8;}
void rule_changer::on_srcip_3_editingFinished(){tbi.rule.src_ip.ip = tbi.rule.src_ip.ip & 0xFFFFFF00 + ui->srcip_3->text().toInt();}
void rule_changer::on_srcip_mask_editingFinished(){tbi.rule.src_ip.mask = ui->srcip_mask->text().toInt();}
void rule_changer::on_dstip_0_editingFinished(){tbi.rule.dst_ip.ip = tbi.rule.dst_ip.ip & 0x00FFFFFF + ui->dstip_0->text().toInt() << 24;}
void rule_changer::on_dstip_1_editingFinished(){tbi.rule.dst_ip.ip = tbi.rule.dst_ip.ip & 0x00FFFFFF + ui->dstip_0->text().toInt() << 16;}
void rule_changer::on_dstip_2_editingFinished(){tbi.rule.dst_ip.ip = tbi.rule.dst_ip.ip & 0x00FFFFFF + ui->dstip_0->text().toInt() << 8;}
void rule_changer::on_dstip_3_editingFinished(){tbi.rule.dst_ip.ip = tbi.rule.dst_ip.ip & 0x00FFFFFF + ui->dstip_0->text().toInt();}
void rule_changer::on_dstip_mask_editingFinished(){tbi.rule.dst_ip.mask = ui->dstip_mask->text().toInt();}
void rule_changer::on_srcports_editingFinished()
{
    if(ui->srcports->text().isEmpty())
        return;
    if(!rule_adder::check_range(ui->srcports->text(), tbi.rule.src_ports, &tbi.rule.src_port_len)){
        QMessageBox::critical(this, "Input error", "range format error!");
        ui->srcports->setText("");
    }
}

void rule_changer::on_dstports_editingFinished()
{
    if(ui->dstports->text().isEmpty())
        return;
    if(!rule_adder::check_range(ui->dstports->text(), tbi.rule.dst_ports, &tbi.rule.dst_port_len)){
        QMessageBox::critical(this, "Input error", "range format error!");
        ui->dstports->setText("");
    }
}

void rule_changer::on_action_currentIndexChanged(int index)
{
    tbi.rule.action = (tbi.rule.action & 0b10) ^ index;
}

void rule_changer::on_log_currentIndexChanged(int index)
{
    tbi.rule.action = (tbi.rule.action & 0b01) ^ index;
}

void rule_changer::on_timeout_editingFinished()
{
    if(ui->timeout->dateTime().toSecsSinceEpoch() - QDateTime::currentSecsSinceEpoch() <= 0){
        QMessageBox::warning(this, "warning", "Cannot set expiration before current time!");
    }
    tbi.rule.timeout = ui->timeout->dateTime().toSecsSinceEpoch() - QDateTime::currentSecsSinceEpoch();
}

void rule_changer::on_btn_change_rule_clicked()
{
    if(ui->srcip_0->text().isEmpty() ||
       ui->srcip_1->text().isEmpty() ||
       ui->srcip_2->text().isEmpty() ||
       ui->srcip_3->text().isEmpty() ||
       ui->srcip_mask->text().isEmpty() ||
       ui->dstip_0->text().isEmpty() ||
       ui->dstip_1->text().isEmpty() ||
       ui->dstip_2->text().isEmpty() ||
       ui->dstip_3->text().isEmpty() ||
       ui->dstip_mask->text().isEmpty() ||
       (ui->srcports->text().isEmpty() && ui->proto->currentIndex() != PROTO_ICMP) ||
       (ui->dstports->text().isEmpty() && ui->proto->currentIndex() != PROTO_ICMP) ||
       ui->position->text().isEmpty() ||
       (ui->timeout_isset->isChecked() && ui->timeout->text().isEmpty())){
        QMessageBox::warning(this, "information incomplete", "There is still something not filled!");
        return;
    }
    int ret1, ret2;
    QFile logfile(maninst_path);
    logfile.open(QIODevice::Append | QIODevice::Text);
    rule_tbd tbd;
    tbd.hp = ui->hook->currentIndex();
    tbd.pos = ui->position->text().toInt();
    tbd.proto = ui->proto->currentIndex();
    tbi.insert_pos = ui->position->text().toInt();
    ret1 = ioctl(devfd, IOCTL_DEL_RULE, &tbd);
    ret2 = ioctl(devfd, IOCTL_ADD_RULE, &tbi);
    if(!ret2 || ret1){
        logfile.write(manlog_generator().toStdString().c_str());
        logfile.write(", FAILED TO CHANGE\n");
        logfile.close();
        QMessageBox::warning(this, "error", "Error occured while adding a rule, errno " + QString::number(ret1) + "," + QString::number(ret2));
    }
    else{
        logfile.write(manlog_generator().toStdString().c_str());
        logfile.write("\n");
        logfile.close();
        QMessageBox::information(this, "rule added", "Successfully added a rule. You can observe it on the main widget now.");
    }
}

QString rule_changer::manlog_generator(){
    QString ret = sectime_tostring(QDateTime::currentSecsSinceEpoch());
    ret += ": ";
    switch(ui->proto->currentIndex()){
    case RULE_TCP:
    case RULE_UDP:{
        if(ui->proto == RULE_TCP)
            ret += "new TCP rule, ";
        else
            ret += "new UDP rule, ";
        ret += "source ip " + ui->srcip_0->text() + "." + ui->srcip_1->text() + "." + ui->srcip_2->text() + "." + ui->srcip_3->text() + "/" + ui->srcip_mask->text() + ", ";
        ret += "dest ip " + ui->dstip_0->text() + "." + ui->dstip_1->text() + "." + ui->dstip_2->text() + "." + ui->dstip_3->text() + "/" + ui->dstip_mask->text() + ", ";
        ret += "source port " + ui->srcports->text() + ", ";
        ret += "dest port " + ui->dstports->text() + ", ";
        ret += "hook " + ui->hook->currentText() + ", ";
        ret += "action" + ui->action->currentText() + ", ";
        ret += ui->log->currentText() + ", ";
        ret += "position " + ui->position->text() + ", ";
        if(ui->timeout_isset->isChecked())
            ret += "timeout " + ui->timeout->text();
        else
            ret += "timeout not set";
        break;
    }
    case RULE_ICMP:{
        ret += "source ip " + ui->srcip_0->text() + "." + ui->srcip_1->text() + "." + ui->srcip_2->text() + "." + ui->srcip_3->text() + "/" + ui->srcip_mask->text() + ", ";
        ret += "dest ip " + ui->dstip_0->text() + "." + ui->dstip_1->text() + "." + ui->dstip_2->text() + "." + ui->dstip_3->text() + "/" + ui->dstip_mask->text() + ", ";
        ret += "hook " + ui->hook->currentText() + ", ";
        ret += "action" + ui->action->currentText() + ", ";
        ret += ui->log->currentText() + ", ";
        ret += "position " + ui->position->text() + ", ";
        if(ui->timeout_isset->isChecked())
            ret += "timeout " + ui->timeout->text();
        else
            ret += "timeout not set";
        break;
    }
    }
    return ret;
}
