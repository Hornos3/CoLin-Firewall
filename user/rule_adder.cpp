#include "rule_adder.h"
#include "ui_rule_adder.h"

rule_adder::rule_adder(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::rule_adder)
{
    ui->setupUi(this);
    srcip[0] = ui->srcip_0;
    srcip[1] = ui->srcip_1;
    srcip[2] = ui->srcip_2;
    srcip[3] = ui->srcip_3;
    srcip[4] = ui->srcip_mask;
    dstip[0] = ui->dstip_0;
    dstip[1] = ui->dstip_1;
    dstip[2] = ui->dstip_2;
    dstip[3] = ui->dstip_3;
    dstip[4] = ui->dstip_mask;
    QIntValidator* validator_255 = new QIntValidator(0, 255, this);
    for(int i=0; i<5; i++){
        srcip[i]->setValidator(validator_255);
        dstip[i]->setValidator(validator_255);
    }
    QIntValidator* validator_32 = new QIntValidator(0, 32, this);
    srcip[4]->setValidator(validator_32);
    dstip[4]->setValidator(validator_32);
    QIntValidator* validator_int = new QIntValidator(0, std::numeric_limits<int>::max(), this);
    ui->timeout->setValidator(validator_int);
    ui->position->setValidator(validator_int);
    ui->timeout_isset->setChecked(false);
    ui->timeout->setEnabled(false);
    memset(&tbi, 0, sizeof(rule_tbi));
}

bool rule_adder::check_range(QString input, port_range dest[MAX_RANGE_IN_A_RULE], unsigned* range_len){
    QStringList ranges = input.split(",");
    if(ranges.length() > MAX_RANGE_IN_A_RULE)
        return false;
    for(int i=0; i<ranges.length(); i++){
        QStringList numbers = ranges[i].split("~");
        if(numbers.size() == 1){
            bool ok;
            int number = numbers[0].toInt(&ok);
            if(!ok || number < 0 || number > 65535){
                return false;
            }
            dest[i].start = dest[i].end = number;
        }else if(numbers.size() == 2){
            bool ok1, ok2;
            int number1 = numbers[0].toInt(&ok1);
            int number2 = numbers[1].toInt(&ok2);
            if(!ok1 || !ok2 || number1 < 0 || number1 > 65536 || number2 < 0 ||
                    number2 > 65535 || number1 > number2){
                return false;
            }
            dest[i].start = number1;
            dest[i].end = number2;
        }else{
            return false;
        }
    }
    *range_len = ranges.length();
    return true;
}

rule_adder::~rule_adder()
{
    delete ui;
}

void rule_adder::on_srcports_editingFinished()
{
    if(ui->srcports->text().isEmpty())
        return;
    if(!check_range(ui->srcports->text(), tbi.rule.src_ports, &tbi.rule.src_port_len)){
        QMessageBox::critical(this, "Input error", "range format error!");
        ui->srcports->setText("");
    }
}

void rule_adder::on_dstports_editingFinished()
{
    if(ui->dstports->text().isEmpty())
        return;
    if(!check_range(ui->dstports->text(), tbi.rule.dst_ports, &tbi.rule.dst_port_len)){
        QMessageBox::critical(this, "Input error", "range format error!");
        ui->dstports->setText("");
    }
}

void rule_adder::on_srcip_0_editingFinished()
{
    bool ok;
    int target = ui->srcip_0->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 255)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->srcip_0->setText("");
        return;
    }
    tbi.rule.src_ip.ip = (tbi.rule.src_ip.ip & 0x00FFFFFF) ^ target << 24;
}

void rule_adder::on_srcip_1_editingFinished()
{
    bool ok;
    int target = ui->srcip_1->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 255)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->srcip_1->setText("");
        return;
    }
    tbi.rule.src_ip.ip = (tbi.rule.src_ip.ip & 0xFF00FFFF) ^ target << 16;
}

void rule_adder::on_srcip_2_editingFinished()
{
    bool ok;
    int target = ui->srcip_2->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 255)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->srcip_2->setText("");
        return;
    }
    tbi.rule.src_ip.ip = (tbi.rule.src_ip.ip & 0xFFFF00FF) ^ target << 8;
}

void rule_adder::on_srcip_3_editingFinished()
{
    bool ok;
    int target = ui->srcip_3->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 255)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->srcip_3->setText("");
        return;
    }
    tbi.rule.src_ip.ip = (tbi.rule.src_ip.ip & 0xFFFFFF00) ^ target;
}

void rule_adder::on_srcip_mask_editingFinished()
{
    bool ok;
    int target = ui->srcip_mask->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 32)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->srcip_mask->setText("");
        return;
    }
    tbi.rule.src_ip.mask = target;
}

void rule_adder::on_dstip_0_editingFinished()
{
    bool ok;
    int target = ui->dstip_0->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 255)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->dstip_0->setText("");
        return;
    }
    tbi.rule.dst_ip.ip = (tbi.rule.dst_ip.ip & 0x00FFFFFF) ^ target << 24;
}

void rule_adder::on_dstip_1_editingFinished()
{
    bool ok;
    int target = ui->dstip_1->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 255)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->dstip_1->setText("");
        return;
    }
    tbi.rule.dst_ip.ip = (tbi.rule.dst_ip.ip & 0xFF00FFFF) ^ target << 16;
}

void rule_adder::on_dstip_2_editingFinished()
{
    bool ok;
    int target = ui->dstip_2->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 255)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->dstip_2->setText("");
        return;
    }
    tbi.rule.dst_ip.ip = (tbi.rule.dst_ip.ip & 0xFFFF00FF) ^ target << 8;
}

void rule_adder::on_dstip_3_editingFinished()
{
    bool ok;
    int target = ui->dstip_3->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 255)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->dstip_3->setText("");
        return;
    }
    tbi.rule.dst_ip.ip = (tbi.rule.dst_ip.ip & 0xFFFFFF00) ^ target;
}

void rule_adder::on_dstip_mask_editingFinished()
{
    bool ok;
    int target = ui->dstip_mask->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 32)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->dstip_mask->setText("");
        return;
    }
    tbi.rule.dst_ip.mask = target;
}

void rule_adder::on_proto_currentIndexChanged(int index)
{
    tbi.rule.protocol = index;
    if(index == PROTO_ICMP){
        ui->srcports->setText("");
        ui->dstports->setText("");
        ui->srcports->setEnabled(false);
        ui->dstports->setEnabled(false);
    }else{
        ui->srcports->setEnabled(true);
        ui->dstports->setEnabled(true);
    }
}

void rule_adder::on_hook_currentIndexChanged(int index)
{
    tbi.rule.hook = index;
    qDebug() << index;
}

void rule_adder::on_action_currentIndexChanged(int index)
{
    tbi.rule.action = (tbi.rule.action & 0b10) ^ index;
}

void rule_adder::on_log_currentIndexChanged(int index)
{
    tbi.rule.action = (tbi.rule.action & 0b01) ^ (index << 1);
}

void rule_adder::on_timeout_isset_stateChanged(int arg1)
{
    Q_UNUSED(arg1);
    ui->timeout->setText("");
    ui->timeout->setEnabled(ui->timeout_isset->isChecked());
    if(!ui->timeout->isEnabled())
        tbi.rule.timeout = 0;
}

void rule_adder::on_timeout_editingFinished()
{
    if(ui->timeout->text().isEmpty())
        return;
    bool ok;
    int target = ui->timeout->text().toInt(&ok);
    if(!ok || target < 0)
        return;
    tbi.rule.timeout = target;
}

void rule_adder::on_position_editingFinished()
{
    bool ok;
    int target = ui->position->text().toInt(&ok);
    if(!ok || target < 0)
        return;
    tbi.insert_pos = target;
}

void rule_adder::on_btn_add_rule_clicked()
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
    int ret;
    QFile logfile(maninst_path);
    logfile.open(QIODevice::Append | QIODevice::Text);
    if(tbi.rule.hook == HOOK_CNT){  // Add rules in all hooks
        for(int i=0; i<HOOK_CNT; i++){
            tbi.rule.hook = i;
            ret = ioctl(devfd, IOCTL_ADD_RULE, &tbi);
            if(!ret){
                QMessageBox::warning(this, "error", "Error occured while adding a rule for "
                                     + hook_names[i] + ", errno " + QString::number(ret));
                logfile.write(manlog_generator().toStdString().c_str());
                logfile.write("\n");
                logfile.close();
                return;
            }
        }
        QMessageBox::information(this, "rule added", "Successfully added rules. You can observe it on the main widget now.");
        logfile.write(manlog_generator().toStdString().c_str());
        logfile.write("\n");
        logfile.close();
        return;
    }else{
        ret = ioctl(devfd, IOCTL_ADD_RULE, &tbi);
        if(!ret){
            logfile.write(manlog_generator().toStdString().c_str());
            logfile.write(", FAILED TO ADD\n");
            logfile.close();
            QMessageBox::warning(this, "error", "Error occured while adding a rule, errno " + QString::number(ret));
        }
        else{
            logfile.write(manlog_generator().toStdString().c_str());
            logfile.write("\n");
            logfile.close();
            QMessageBox::information(this, "rule added", "Successfully added a rule. You can observe it on the main widget now.");
        }
    }
}

QString rule_adder::manlog_generator(){
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
            ret += "timeout " + ui->timeout->text() + "s";
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
            ret += "timeout " + ui->timeout->text() + "s";
        else
            ret += "timeout not set";
        break;
    }
    }
    return ret;
}

void rule_adder::on_srcip_0_returnPressed(){ui->srcip_1->setFocus();}
void rule_adder::on_srcip_1_returnPressed(){ui->srcip_2->setFocus();}
void rule_adder::on_srcip_2_returnPressed(){ui->srcip_3->setFocus();}
void rule_adder::on_srcip_3_returnPressed(){ui->srcip_mask->setFocus();}
void rule_adder::on_srcip_mask_returnPressed(){ui->srcports->setFocus();}
void rule_adder::on_srcports_returnPressed(){ui->dstip_0->setFocus();}
void rule_adder::on_dstip_0_returnPressed(){ui->dstip_1->setFocus();}
void rule_adder::on_dstip_1_returnPressed(){ui->dstip_2->setFocus();}
void rule_adder::on_dstip_2_returnPressed(){ui->dstip_3->setFocus();}
void rule_adder::on_dstip_3_returnPressed(){ui->dstip_mask->setFocus();}
void rule_adder::on_dstip_mask_returnPressed(){ui->dstports->setFocus();}
void rule_adder::on_dstports_returnPressed(){if(ui->timeout->isEnabled()) ui->timeout->setFocus(); else ui->position->setFocus();}
void rule_adder::on_proto_activated(int index){Q_UNUSED(index);}
void rule_adder::on_hook_activated(int index){Q_UNUSED(index);}
void rule_adder::on_action_activated(int index){Q_UNUSED(index);}
void rule_adder::on_log_activated(int index){Q_UNUSED(index);}
void rule_adder::on_timeout_returnPressed(){ui->position->setFocus();}

