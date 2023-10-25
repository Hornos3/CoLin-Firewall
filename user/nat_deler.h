#ifndef NAT_DELER_H
#define NAT_DELER_H

#include <QWidget>
#include <QValidator>
#include <QMessageBox>
#include <QHostAddress>

#include "common.h"
#include "nat_adder.h"

namespace Ui {
class nat_deler;
}

class nat_deler : public QWidget
{
    Q_OBJECT

public:
    explicit nat_deler(QWidget *parent = nullptr);
    ~nat_deler();

private slots:
    void on_position_editingFinished();

private:
    Ui::nat_deler *ui;
    nat_config nc;

    QString manlog_generator();
};

#endif // NAT_DELER_H
