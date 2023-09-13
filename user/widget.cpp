#include "widget.h"
#include "ui_widget.h"

#include <QDebug>

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    hooks = new QButtonGroup(this);
    hooks->addButton(ui->pre_routing, 0);
    hooks->addButton(ui->local_in, 1);
    hooks->addButton(ui->local_out, 2);
    hooks->addButton(ui->forward, 3);
    hooks->addButton(ui->post_routing, 4);
    protos = new QButtonGroup(this);
    protos->addButton(ui->btn_tcp, 0);
    protos->addButton(ui->btn_udp, 1);
    protos->addButton(ui->btn_icmp, 2);
    infos = new QButtonGroup(this);
    infos->addButton(ui->btn_connections, 0);
    infos->addButton(ui->btn_rules, 1);
    infos->addButton(ui->btn_logs, 2);

    devfd = open("/dev/lhy_memcdev", O_RDWR);
    if(devfd <= 0){
        QMessageBox::critical(this, "Fatal Error",
                              "Failed to open device /dev/lhy_memcdev! devfd = " + QString::number(devfd) + ", " + strerror(errno));
        exit(1);
    }

    get_all_configs();
    memset(rule_path, 0, 256);
    get_rule_path();
    for(int i=0; i<HOOK_CNT; i++)
        for(int j=0; j<PROTOCOL_SUPPORTED; j++){
            default_strategy[i][j] = ioctl(devfd, IOCTL_GET_DEFAULT + IOCTL_PROTO(j) + i, 0b10000000);
        }

    for(int i=0; i<HOOK_CNT; i++)
        for(int j=0; j<PROTOCOL_SUPPORTED; j++){
            rule_models[i][j] = new QStandardItemModel(this);
            rule_models[i][j]->setColumnCount(rule_headers[j].length());
            for(int k=0; k<rule_headers[j].length(); k++)
                rule_models[i][j]->setHeaderData(k, Qt::Horizontal, rule_headers[j].at(k));
        }
    for(int i=0; i<PROTOCOL_SUPPORTED; i++){
        connection_models[i] = new QStandardItemModel(this);
        connection_models[i]->setColumnCount(connection_headers[i].length());
        for(int k=0; k<connection_headers[i].length(); k++)
            connection_models[i]->setHeaderData(k, Qt::Horizontal, connection_headers[i].at(k));
        log_models[i] = new QStandardItemModel(this);
        log_models[i]->setColumnCount(log_headers[i].length());
        for(int k=0; k<log_headers[i].length(); k++)
            log_models[i]->setHeaderData(k, Qt::Horizontal, log_headers[i].at(k));
    }

    current_hook = 0;
    current_proto = 0;
    current_info = 0;
    ui->pre_routing->click();
    ui->btn_tcp->click();
    ui->btn_connections->click();
    initialize_click = false;
    start_update_table(0, 0, 0);

    ui->infotable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->infotable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::get_all_configs(){
    for(int i=0; i<CONFIG_CNT; i++)
        *(configs[i]) = ioctl(devfd, IOCTL_GET_CONFIG, i);
}

void Widget::get_rule_path(){
    char str[256];
    long ret = ioctl(devfd, IOCTL_GET_RULE_PATH, str);
    if(ret < 0){
        QMessageBox::critical(this, "rule path failed to get", "Unable to get rule path from the kernel module!");
        return;
    }
    strcpy(rule_path, str);
    rule_path[ret] = '\0';
}

void Widget::set_rule_path(QString path){
    long ret = ioctl(devfd, IOCTL_SET_RULE_PATH, path.toStdString().c_str());
    if(ret)
        QMessageBox::critical(this, "rule path failed to set", "Unable to set rule path for kernel! Check whether the path is valid");
}

void Widget::on_pre_routing_clicked(){
    current_hook = HP_PRE_ROUTING;
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_local_out_clicked(){
    current_hook = HP_LOCAL_OUT;
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_local_in_clicked(){
    current_hook = HP_LOCAL_IN;
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_forward_clicked(){
    current_hook = HP_FORWARD;
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_post_routing_clicked(){
    current_hook = HP_POST_ROUTING;
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_btn_tcp_clicked(){
    current_proto = PROTO_TCP;
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_btn_udp_clicked(){
    current_proto = PROTO_UDP;
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_btn_icmp_clicked(){
    current_proto = PROTO_ICMP;
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::start_update_table(unsigned info, unsigned hook, unsigned proto){
    if(initialize_click)
        return;
    if(update_timer.isActive()){
        update_timer.stop();
        disconnect(&update_timer, &QTimer::timeout, this, nullptr);
    }
    // update the table every second
    update_table(info, hook, proto);

    connect(&update_timer, &QTimer::timeout, this, [this, info, hook, proto](){
        update_table(info, hook, proto);
    });
    update_timer.setInterval(frontend_update_interval);
    update_timer.start();
}

void Widget::update_table(unsigned info, unsigned hook, unsigned proto){
    switch(info){
    case INFO_CON:
        ui->infotable->setModel(connection_models[proto]);
        con_table::update_connections(proto);
        break;
    case INFO_RULE:
        ui->infotable->setModel(rule_models[hook][proto]);
        rule_table::update_rules(hook, proto);
        break;
    case INFO_LOG:
        ui->infotable->setModel(log_models[proto]);
        log_table::update_log(proto);
        break;
    }
    ui->infotable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->infotable->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->infotable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->infotable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->infotable->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->infotable->viewport()->update();
}

void Widget::on_btn_addrule_clicked()
{
    rule_adder* rule_adder_ui = new rule_adder(nullptr);
    rule_adder_ui->show();
}

void Widget::on_btn_deleterule_clicked()
{
    rule_deler* rule_deler_ui = new rule_deler(nullptr);
    rule_deler_ui->show();
}

void Widget::on_btn_settings_clicked()
{
    settings* settings_ui = new settings(nullptr);
    settings_ui->show();
}

void Widget::on_btn_connections_clicked()
{
    current_info = INFO_CON;
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_btn_rules_clicked()
{
    current_info = INFO_RULE;
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_btn_logs_clicked()
{
    current_info = INFO_LOG;
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_infotable_customContextMenuRequested(const QPoint &pos)
{
    Q_UNUSED(pos);
    if(ui->btn_rules->isDown()){
        QModelIndexList selectedIndexes = ui->infotable->selectionModel()->selectedIndexes();
        if(selectedIndexes.length() == 0)
            return;
        QMenu menu;
        QAction* del_action = menu.addAction("Delete this rule");
        connect(del_action, &QAction::triggered, this, [this, selectedIndexes](){
            for(int i=0; i<selectedIndexes.length(); i++){
                QModelIndex idx = selectedIndexes[i];
                rule_tbd tbd = {(unsigned)protos->checkedId(), (unsigned)hooks->checkedId(), (unsigned)idx.row() + 1};
                rule_deler::del_rule(&tbd);
            }
        });
        menu.exec(QCursor::pos());
    }
}
