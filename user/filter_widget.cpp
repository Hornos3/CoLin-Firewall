#include "filter_widget.h"
#include "ui_filter_widget.h"

filter_widget::filter_widget(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::filter_widget)
{
    ui->setupUi(this);
}

filter_widget::~filter_widget()
{
    delete ui;
}

void filter_widget::initialize_table(QStandardItemModel* model){
    ui->filter_table->setModel(model);
}
