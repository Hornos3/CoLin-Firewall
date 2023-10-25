#ifndef RULE_ADDER_H
#define RULE_ADDER_H

#include <QString>
#include <QWidget>
#include <QCheckBox>
#include <QLineEdit>
#include <QMessageBox>
#include <QIntValidator>

#include "common.h"

namespace Ui {
class rule_adder;
}

class rule_adder : public QWidget
{
    Q_OBJECT

public:
    explicit rule_adder(QWidget *parent = nullptr);
    ~rule_adder();

private slots:
    void on_srcports_editingFinished();

    void on_dstports_editingFinished();

    void on_srcip_0_editingFinished();

    void on_srcip_1_editingFinished();

    void on_srcip_2_editingFinished();

    void on_srcip_3_editingFinished();

    void on_srcip_mask_editingFinished();

    void on_dstip_0_editingFinished();

    void on_dstip_1_editingFinished();

    void on_dstip_2_editingFinished();

    void on_dstip_3_editingFinished();

    void on_dstip_mask_editingFinished();

    void on_proto_currentIndexChanged(int index);

    void on_hook_currentIndexChanged(int index);

    void on_action_currentIndexChanged(int index);

    void on_log_currentIndexChanged(int index);

    void on_timeout_isset_stateChanged(int arg1);

    void on_timeout_editingFinished();

    void on_position_editingFinished();

    void on_btn_add_rule_clicked();

    void on_srcip_0_returnPressed();

    void on_srcip_1_returnPressed();

    void on_srcip_2_returnPressed();

    void on_srcip_3_returnPressed();

    void on_srcip_mask_returnPressed();

    void on_srcports_returnPressed();

    void on_dstip_0_returnPressed();

    void on_dstip_1_returnPressed();

    void on_dstip_2_returnPressed();

    void on_dstip_3_returnPressed();

    void on_dstip_mask_returnPressed();

    void on_dstports_returnPressed();

    void on_timeout_returnPressed();

    void on_proto_activated(int index);

    void on_hook_activated(int index);

    void on_action_activated(int index);

    void on_log_activated(int index);

private:
    rule_tbi tbi;
    QLineEdit* srcip[5];
    QLineEdit* dstip[5];
    Ui::rule_adder *ui;

    bool check_range(QString input, port_range dest[MAX_RANGE_IN_A_RULE], unsigned* range_len);
    QString manlog_generator();

};

#endif // RULE_ADDER_H
