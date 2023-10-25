#ifndef RULE_CHANGER_H
#define RULE_CHANGER_H

#include <QWidget>

#include "common.h"
#include "log_filter.h"
#include "rule_adder.h"

namespace Ui {
class rule_changer;
}

class rule_changer : public QWidget
{
    Q_OBJECT

public:
    explicit rule_changer(QWidget *parent = nullptr);
    ~rule_changer();

private slots:
    void on_position_editingFinished();

    void on_timeout_isset_stateChanged(int arg1);

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

    void on_srcports_editingFinished();

    void on_dstports_editingFinished();

    void on_action_currentIndexChanged(int index);

    void on_log_currentIndexChanged(int index);

    void on_timeout_editingFinished();

    void on_btn_change_rule_clicked();

private:
    Ui::rule_changer *ui;
    rule_tbi tbi;
    void activate_choices(bool activate);
    void fill_choices();
    void update_tbi();
    QString manlog_generator();
};

#endif // RULE_CHANGER_H
