#include "nat_deler.h"
#include "ui_nat_deler.h"

nat_deler::nat_deler(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::nat_deler)
{
    ui->setupUi(this);
    QIntValidator* validator_65535 = new QIntValidator(1, 65535, this);
    ui->position->setValidator(validator_65535);
    nc.NAT_mode = NAT_PAT;
    nc.next = nc.prev = nullptr;
}

nat_deler::~nat_deler()
{
    delete ui;
}


void nat_deler::on_position_editingFinished()
{
    if(ui->position->text().isEmpty() || ui->position->text().toInt() > nat_model->rowCount())
        return;
    QString lan = nat_model->item(ui->position->text().toInt()-1, 0)->text();
    QString gateway = nat_model->item(ui->position->text().toInt()-1, 1)->text();
    QList<QString> sp = lan.split("/");
    QString lan_ip = sp[0];
    int lan_mask = sp[1].toInt();
    nc.config.pc.lan.ip = nat_adder::ip_atohl(lan_ip);
    nc.config.pc.lan.mask = lan_mask;
    nc.config.pc.wan = nat_adder::ip_atohl(gateway);
    QFile logfile(maninst_path);
    logfile.open(QIODevice::Append | QIODevice::Text);
    if(ioctl(devfd, IOCTL_ADDDEL_NAT, (size_t)(&nc) | 1)){
        logfile.write(manlog_generator().toStdString().c_str());
        logfile.write(", FAILED TO DELETE\n");
        logfile.close();
        QMessageBox::critical(this, "Error", "Failed to delete a nat config, there may be bugs somewhere!");
    }else{
        logfile.write(manlog_generator().toStdString().c_str());
        logfile.write("\n");
        logfile.close();
        QMessageBox::information(this, "note", "Successfully deleted a nat config.");
    }
}

QString nat_deler::manlog_generator(){
    if(ui->position->text().toInt() <= 0 || ui->position->text().toInt() > nat_model->rowCount())
        return "Line number out of bound, there may be bugs in this Qt GUI!";
    QString ret = sectime_tostring(QDateTime::currentSecsSinceEpoch());
    ret += ": ";
    ret += "delete NAT rule, ";
    ret += "LAN " + nat_model->item(ui->position->text().toInt()-1, 0)->text() + ", ";
    ret += "Gateway " + nat_model->item(ui->position->text().toInt()-1, 1)->text();
    return ret;
}
