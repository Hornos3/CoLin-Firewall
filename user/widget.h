#ifndef WIDGET_H
#define WIDGET_H

#include <QFile>
#include <QMenu>
#include <cerrno>
#include <QTimer>
#include <string>
#include <QAction>
#include <QWidget>
#include <fcntl.h>
#include <QString>
#include <unistd.h>
#include <sys/ioctl.h>
#include <QPushButton>
#include <QMessageBox>
#include <rule_table.h>
#include <QButtonGroup>
#include <QStandardItemModel>

#include "common.h"
#include "settings.h"
#include "con_table.h"
#include "log_table.h"
#include "rule_adder.h"
#include "rule_deler.h"
#include "rule_table.h"

QT_BEGIN_NAMESPACE
namespace Ui { class Widget; }
QT_END_NAMESPACE

class Widget : public QWidget
{
    Q_OBJECT

public:
    Widget(QWidget *parent = nullptr);
    ~Widget();

private slots:
    void on_pre_routing_clicked();
    void on_local_out_clicked();
    void on_local_in_clicked();
    void on_forward_clicked();
    void on_post_routing_clicked();
    void on_btn_tcp_clicked();
    void on_btn_udp_clicked();
    void on_btn_icmp_clicked();

    void on_btn_addrule_clicked();

    void on_btn_deleterule_clicked();

    void on_btn_settings_clicked();

    void on_btn_connections_clicked();

    void on_btn_rules_clicked();

    void on_btn_logs_clicked();

    void on_infotable_customContextMenuRequested(const QPoint &pos);

private:
    Ui::Widget *ui;
    QButtonGroup* hooks;
    QButtonGroup* protos;
    QButtonGroup* infos;
    QPushButton* last_pressed_hook = nullptr;
    QPushButton* last_pressed_info = nullptr;
    QPushButton* last_pressed_proto = nullptr;
    QTimer update_timer;
    unsigned current_proto = 0;
    unsigned current_hook = 0;
    unsigned current_info = 0;
    bool initialize_click = true;

    const QStringList connection_headers[PROTOCOL_SUPPORTED] = {{"Client", "Server", "Last packet at", "Expires at"},
                                                                {"Client", "Server", "Last packet at", "Expires at"},
                                                                {"Client", "Server", "ICMP Type", "Last packet at", "Expires at"}};
    const QStringList rule_headers[PROTOCOL_SUPPORTED] = {
        {"Sender IP", "Sender Port", "Receiver IP", "Receiver Port", "Protocol", "Action", "Log"},
        {"Sender IP", "Sender Port", "Receiver IP", "Receiver Port", "Protocol", "Action", "Log"},
        {"Sender IP", "Receiver IP", "Protocol", "Action", "Log"}
    };
    const QStringList log_headers[PROTOCOL_SUPPORTED] = {
        {"Time", "Sender", "Receiver", "Action", "Seq", "Ack Seq", "Symbols", "Packet Length"},
        {"Time", "Sender", "Receiver", "Action", "Packet Length"},
        {"Time", "Sender", "Receiver", "ICMP Type", "ICMP Code", "Action", "Packet Length"}
    };

#define COLUMN_COUNT(info, proto) \
    (info == INFO_CON) ? (connection_headers[proto].length()) : \
    (info == INFO_RULE) ? (rule_headers[proto].length()) : \
    log_headers[proto].length()

    void get_all_configs();
    void get_rule_path();
    void set_rule_path(QString path);

    void start_update_table(unsigned, unsigned, unsigned);
    void update_table(unsigned, unsigned, unsigned);
};
#endif // WIDGET_H
