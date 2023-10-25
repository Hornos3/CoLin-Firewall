#include "rule_deler.h"
#include "ui_rule_deler.h"

rule_deler::rule_deler(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::rule_deler)
{
    ui->setupUi(this);
    QIntValidator* validator_65535 = new QIntValidator(1, 65535, this);
    ui->position->setValidator(validator_65535);
    tbd.hp = 0;
    tbd.proto = 0;
    tbd.pos = -1;
}

rule_deler::~rule_deler()
{
    delete ui;
}

void rule_deler::on_proto_currentIndexChanged(int index)
{
    tbd.proto = index;
}

void rule_deler::on_hook_currentIndexChanged(int index)
{
    tbd.hp = index;
}

void rule_deler::on_position_editingFinished()
{
    if(ui->position->text().isEmpty()){
        tbd.pos = -1;
        return;
    }
    bool ok;
    int target = ui->position->text().toInt(&ok);
    if(!ok || target <= 0){
        ui->position->setText("");
        return;
    }
    if(rule_models[tbd.hp][tbd.proto]->rowCount() + 1 < target){
        QMessageBox::warning(this, "position error",
                             "position value out of bound! should be no more than " +
                             QString::number(rule_models[tbd.hp][tbd.proto]->rowCount() + 1));
        ui->position->setText("");
        return;
    }
    tbd.pos = target;
}

bool rule_deler::del_rule(rule_tbd* tbd){
    if(tbd->pos <= 0 || tbd->hp > HOOK_CNT || tbd->proto > PROTOCOL_SUPPORTED){
        QMessageBox::warning(nullptr, "error", "information format error!");
        return false;
    }
    QString log_content = manlog_generator();
    qDebug() << log_content;
    int ret = ioctl(devfd, IOCTL_DEL_RULE, tbd);
    QFile logfile(maninst_path);
    logfile.open(QIODevice::Append | QIODevice::Text);
    if(ret){
        logfile.write(log_content.toStdString().c_str());
        logfile.write(", FAILED TO DELETE\n");
        logfile.close();
        QMessageBox::critical(nullptr, "error", "Error occured while deleting thie rule, errno " + QString::number(ret));
        return false;
    }
    else{
        logfile.write(log_content.toStdString().c_str());
        logfile.write("\n");
        logfile.close();
        QMessageBox::information(nullptr, "rule deleted", "Successfully deleted this rule.");
    }
    return true;
}

QString rule_deler::manlog_generator(){
    if(ui->position->text().toInt() > rule_models[ui->hook->currentIndex()][ui->proto->currentIndex()]->rowCount() || ui->position->text().toInt() <= 0)
        return "Line number out of bound, there may be bugs in this Qt GUI!";
    QString ret = sectime_tostring(QDateTime::currentSecsSinceEpoch());
    ret += ": ";
    switch(ui->proto->currentIndex()){
    case RULE_TCP:
    case RULE_UDP:{
        if(ui->proto == RULE_TCP)
            ret += "delete TCP rule, ";
        else
            ret += "delete UDP rule, ";
        ret += "source ip " + rule_models[ui->hook->currentIndex()][ui->proto->currentIndex()]->item(ui->position->text().toInt()-1, 0)->text() + ", ";
        ret += "dest ip " + rule_models[ui->hook->currentIndex()][ui->proto->currentIndex()]->item(ui->position->text().toInt()-1, 2)->text() + ", ";
        ret += "source port " + rule_models[ui->hook->currentIndex()][ui->proto->currentIndex()]->item(ui->position->text().toInt()-1, 1)->text() + ", ";
        ret += "dest port " + rule_models[ui->hook->currentIndex()][ui->proto->currentIndex()]->item(ui->position->text().toInt()-1, 3)->text() + ", ";
        ret += "action " + rule_models[ui->hook->currentIndex()][ui->proto->currentIndex()]->item(ui->position->text().toInt()-1, 5)->text() + ", ";
        ret += rule_models[ui->hook->currentIndex()][ui->proto->currentIndex()]->item(ui->position->text().toInt()-1, 6)->text() + ", ";  // log or not
        ret += "position " + ui->position->text();
        break;
    }
    case RULE_ICMP:{
        ret += "source ip " + rule_models[ui->hook->currentIndex()][ui->proto->currentIndex()]->item(ui->position->text().toInt()-1, 0)->text() + ", ";
        ret += "dest ip " + rule_models[ui->hook->currentIndex()][ui->proto->currentIndex()]->item(ui->position->text().toInt()-1, 2)->text() + ", ";
        ret += "action " + rule_models[ui->hook->currentIndex()][ui->proto->currentIndex()]->item(ui->position->text().toInt()-1, 5)->text() + ", ";
        ret += rule_models[ui->hook->currentIndex()][ui->proto->currentIndex()]->item(ui->position->text().toInt()-1, 6)->text() + ", ";  // log or not
        ret += "position " + ui->position->text();
        break;
    }
    }
    return ret;
}

void rule_deler::on_btn_del_rule_clicked()
{
    del_rule(&tbd);
}
