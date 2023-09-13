#ifndef RULE_DELER_H
#define RULE_DELER_H

#include <QWidget>
#include <QMessageBox>

#include "common.h"

namespace Ui {
class rule_deler;
}

class rule_deler : public QWidget
{
    Q_OBJECT

public:
    explicit rule_deler(QWidget *parent = nullptr);
    static bool del_rule(rule_tbd* tbd);
    ~rule_deler();

private slots:
    void on_proto_currentIndexChanged(int index);

    void on_hook_currentIndexChanged(int index);

    void on_position_editingFinished();

    void on_btn_del_rule_clicked();

private:
    rule_tbd tbd;
    Ui::rule_deler *ui;
};

#endif // RULE_DELER_H
