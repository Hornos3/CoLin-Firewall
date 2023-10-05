#ifndef LOG_FILTER_H
#define LOG_FILTER_H

#include <QWidget>
#include <QRegExp>
#include <QDateTime>
#include <QHostAddress>

#include "common.h"
#include "filter_widget.h"

namespace Ui {
class log_filter;
}

class log_filter : public QWidget
{
    Q_OBJECT

public:
    explicit log_filter(QWidget *parent = nullptr);
    ~log_filter();

    static QList<CIDR>* analyse_cidr_str(QString str);
    static QList<port_range>* analyse_portrange_str(QString str);
    static bool is_inCIDR(unsigned int ip, QList<CIDR>* cidrs);
    static bool is_inCIDR(QString ip, QList<CIDR>* cidrs);
    static bool is_inrange(unsigned short port, QList<port_range>* ranges);
    static bool ipport_inrange(QString str, QList<CIDR>* cidrs, QList<port_range>* ranges);
    static QStandardItemModel* deep_copy(unsigned proto);
    bool filter_activated = false;
    unsigned proto;

    bool match(QList<QStandardItem*> log, unsigned proto);
    void show_result();
    void do_filter();

private slots:
    void on_choice_tcp_clicked();

    void on_choice_udp_clicked();

    void on_choice_icmp_clicked();

    void on_srcip_stateChanged(int arg1);

    void on_dstip_stateChanged(int arg1);

    void on_srcport_stateChanged(int arg1);

    void on_dstport_stateChanged(int arg1);

    void on_action_stateChanged(int arg1);

    void on_hp_stateChanged(int arg1);

    void on_time_stateChanged(int arg1);

    void on_srcip_filter_editingFinished();

    void on_dstip_filter_editingFinished();

    void on_srcport_filter_editingFinished();

    void on_dstport_filter_editingFinished();

    void on_action_filter_currentIndexChanged(int index);

    void on_hp_filter_currentIndexChanged(int index);

    void on_start_time_editingFinished();

    void on_end_time_editingFinished();

    void on_btn_clear_filter_clicked();

    void on_btn_activate_clicked();

private:
    Ui::log_filter *ui;

    bool srcip_activated = false;
    bool dstip_activated = false;
    bool srcport_activated = false;
    bool dstport_activated = false;
    bool action_activated = false;
    bool hp_activated = false;
    bool time_activated = false;

    QList<CIDR>* srcip = nullptr;
    QList<CIDR>* dstip = nullptr;
    QList<port_range>* srcport = nullptr;
    QList<port_range>* dstport = nullptr;
    int action;
    int hp;
    QDateTime start_time;
    QDateTime end_time;

    filter_widget* widget;
};

#endif // LOG_FILTER_H
