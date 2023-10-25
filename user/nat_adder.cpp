#include "nat_adder.h"
#include "ui_nat_adder.h"

nat_adder::nat_adder(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::nat_adder)
{
    ui->setupUi(this);
    QStringList hostips = get_host_ips();
    ui->host_ips->addItems(hostips);
    QIntValidator* validator_255 = new QIntValidator(0, 255, this);
    ui->ip_0->setValidator(validator_255);
    ui->ip_1->setValidator(validator_255);
    ui->ip_2->setValidator(validator_255);
    ui->ip_3->setValidator(validator_255);
    QIntValidator* validator_32 = new QIntValidator(0, 32, this);
    ui->ip_mask->setValidator(validator_32);
}

nat_adder::~nat_adder()
{
    delete ui;
}

QStringList nat_adder::get_host_ips(){
    QStringList ret;
    QList<QNetworkInterface> interfaces = QNetworkInterface::allInterfaces();
    for (const QNetworkInterface& interface : interfaces){
        QList<QNetworkAddressEntry> entries = interface.addressEntries();
        for (const QNetworkAddressEntry& entry : entries) {
            if(entry.ip().protocol() != QAbstractSocket::IPv4Protocol)
                continue;
            QString ip = entry.ip().toString();
            ret << ip;
        }
    }
    return ret;
}

unsigned nat_adder::ip_atohl(QString ip){
    QHostAddress addr(ip);
    if(addr.isNull() || addr.protocol() != QAbstractSocket::IPv4Protocol){
        qDebug() << "IP address invalid, failed to parse";
        return 0;
    }
    return addr.toIPv4Address();
}

void nat_adder::on_btn_del_rule_clicked()
{
    if(ui->ip_0->text().isEmpty() ||
       ui->ip_1->text().isEmpty() ||
       ui->ip_2->text().isEmpty() ||
       ui->ip_3->text().isEmpty() ||
       ui->ip_mask->text().isEmpty())
        QMessageBox::warning(this, "information incomplete", "There is still something not filled!");
    nc.NAT_mode = NAT_PAT;
    nc.config.pc.wan = ip_atohl(ui->host_ips->currentText());
    QFile logfile(maninst_path);
    logfile.open(QIODevice::Append | QIODevice::Text);
    if(ioctl(devfd, IOCTL_ADDDEL_NAT, &nc)){
        logfile.write(manlog_generator().toStdString().c_str());
        logfile.write(", FAILED TO ADD\n");
        logfile.close();
        QMessageBox::critical(this, "Error", "Failed to add a nat config, the kernel module may has bugs!");
    }else{
        logfile.write(manlog_generator().toStdString().c_str());
        logfile.write("\n");
        logfile.close();
        QMessageBox::information(this, "note", "Successfully added a nat config.");
    }
}

QString nat_adder::manlog_generator(){
    QString ret = sectime_tostring(QDateTime::currentSecsSinceEpoch());
    ret += ": ";
    ret += "new NAT rule, ";
    QHostAddress ipaddr(nc.config.pc.lan.ip);
    ret += "LAN " + ipaddr.toString() + "/" + QString::number(nc.config.pc.lan.mask) + ", ";
    ipaddr.setAddress(nc.config.pc.wan);
    ret += "Gateway " + ipaddr.toString();
    return ret;
}

void nat_adder::on_ip_0_returnPressed(){ui->ip_1->setFocus();}
void nat_adder::on_ip_1_returnPressed(){ui->ip_2->setFocus();}
void nat_adder::on_ip_2_returnPressed(){ui->ip_3->setFocus();}
void nat_adder::on_ip_3_returnPressed(){ui->ip_mask->setFocus();}

void nat_adder::on_ip_0_editingFinished()
{
    bool ok;
    int target = ui->ip_0->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 255)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->ip_0->setText("");
        return;
    }
    nc.config.pc.lan.ip = (nc.config.pc.lan.ip & 0x00FFFFFF) ^ target << 24;
}

void nat_adder::on_ip_1_editingFinished()
{
    bool ok;
    int target = ui->ip_1->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 255)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->ip_1->setText("");
        return;
    }
    nc.config.pc.lan.ip = (nc.config.pc.lan.ip & 0xFF00FFFF) ^ target << 16;
}

void nat_adder::on_ip_2_editingFinished()
{
    bool ok;
    int target = ui->ip_2->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 255)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->ip_2->setText("");
        return;
    }
    nc.config.pc.lan.ip = (nc.config.pc.lan.ip & 0xFFFF00FF) ^ target << 8;
}

void nat_adder::on_ip_3_editingFinished()
{
    bool ok;
    int target = ui->ip_3->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 255)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->ip_3->setText("");
        return;
    }
    nc.config.pc.lan.ip = (nc.config.pc.lan.ip & 0xFFFFFF00) ^ target;
}


void nat_adder::on_ip_mask_editingFinished()
{
    bool ok;
    int target = ui->ip_mask->text().toInt(&ok);
    if(!ok || !(0 <= target && target <= 32)){
        QMessageBox::warning(this, "error", "Invalid input!");
        ui->ip_mask->setText("");
        return;
    }
    nc.config.pc.lan.mask = target;
}
