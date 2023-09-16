#ifndef SETTINGS_H
#define SETTINGS_H

#include <map>
#include <QDir>
#include <string>
#include <fcntl.h>
#include <QWidget>
#include <unistd.h>
#include <QSpinBox>
#include <QFileInfo>
#include <QCheckBox>
#include <QFileDialog>
#include <sys/ioctl.h>
#include <QMessageBox>

#include "common.h"

namespace Ui {
class settings;
}

class settings : public QWidget
{
    Q_OBJECT

public:
    explicit settings(QWidget *parent = nullptr);
    bool set_config(unsigned cid, unsigned val);
    bool set_config(unsigned cid, bool checked);
    bool set_config(QString filepath);
    std::map<unsigned, QSpinBox*> spinbox_maps;
    std::map<unsigned, QCheckBox*> checkbox_maps;
    ~settings();

private slots:
    void on_tcp_timeout_fixed_stateChanged(int arg1);
    void on_udp_timeout_fixed_stateChanged(int arg1);
    void on_rule_path_editingFinished();
    void on_tcp_syn_timeout_editingFinished();
    void on_tcp_fin_timeout_editingFinished();
    void on_tcp_initial_timeout_editingFinished();
    void on_udp_initial_timeout_editingFinished();
    void on_icmp_initial_timeout_editingFinished();
    void on_tcp_max_timeout_editingFinished();
    void on_udp_max_timeout_editingFinished();
    void on_icmp_max_timeout_editingFinished();
    void on_tcp_max_con_editingFinished();
    void on_udp_max_con_editingFinished();
    void on_icmp_max_con_editingFinished();
    void on_tcp_max_logs_editingFinished();
    void on_udp_max_logs_editingFinished();
    void on_icmp_max_logs_editingFinished();
    void on_max_rule_editingFinished();

    void on_btn_savelog_clicked();

    void on_log_autosave_stateChanged(int arg1);

private:
    Ui::settings *ui;
};

#endif // SETTINGS_H
