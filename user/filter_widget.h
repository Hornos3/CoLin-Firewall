#ifndef FILTER_WIDGET_H
#define FILTER_WIDGET_H

#include <QWidget>
#include <QStandardItemModel>

namespace Ui {
class filter_widget;
}

class filter_widget : public QWidget
{
    Q_OBJECT

public:
    explicit filter_widget(QWidget *parent = nullptr);
    ~filter_widget();

    void initialize_table(QStandardItemModel* model);

private:
    Ui::filter_widget *ui;
};

#endif // FILTER_WIDGET_H
