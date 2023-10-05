#ifndef NAT_ADDER_H
#define NAT_ADDER_H

#include <QWidget>
#include <QHostAddress>
#include <QCoreApplication>
#include <QNetworkInterface>

#include "common.h"

namespace Ui {
class nat_adder;
}

class nat_adder : public QWidget
{
    Q_OBJECT

public:
    explicit nat_adder(QWidget *parent = nullptr);
    static QStringList get_host_ips();
    static unsigned ip_atohl(QString ip);
    ~nat_adder();

private slots:
    void on_btn_del_rule_clicked();

    void on_ip_0_returnPressed();

    void on_ip_1_returnPressed();

    void on_ip_2_returnPressed();

    void on_ip_3_returnPressed();

    void on_ip_0_editingFinished();

    void on_ip_1_editingFinished();

    void on_ip_2_editingFinished();

    void on_ip_3_editingFinished();

    void on_ip_mask_editingFinished();

private:
    Ui::nat_adder *ui;
    nat_config nc;
};

#endif // NAT_ADDER_H
