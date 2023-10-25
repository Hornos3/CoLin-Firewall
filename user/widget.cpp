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
    hooks->addButton(ui->post_routing, 1);
    protos = new QButtonGroup(this);
    protos->addButton(ui->btn_tcp, 0);
    protos->addButton(ui->btn_udp, 1);
    protos->addButton(ui->btn_icmp, 2);
    infos = new QButtonGroup(this);
    infos->addButton(ui->btn_connections, 0);
    infos->addButton(ui->btn_rules, 1);
    infos->addButton(ui->btn_logs, 2);
    infos->addButton(ui->btn_nats, 3);

    int shell_ret = shell("insmod ../kernel/lhy_firewall.ko", "Successfully installed the kernel module.",
          "Failed to install the kernel module.");
    if(shell_ret)
        exit(1);

    devfd = open("/dev/lhy_memcdev", O_RDWR);
    if(devfd <= 0){
        QMessageBox::critical(this, "Fatal Error",
                              "Failed to open device /dev/lhy_memcdev! devfd = " + QString::number(devfd) + ", " + strerror(errno));
        exit(2);
    }

    get_all_configs();
    memset(rule_path, 0, 256);
    get_rule_path();
    QFileInfo fi("/etc/lhy_firewall/gui-autosave");
    if(!fi.exists()){
        system("touch /etc/lhy_firewall/gui-autosave");
        system((QString("echo ") + autosave_path + " < /etc/lhy_firewall/gui-autosave").toStdString().c_str());
    }else{
        autosave_path = readall("/etc/lhy_firewall/gui-autosave");
        if(!save_file_valid(autosave_path)){
            qDebug() << "Previous autosave path invalid, switch to default: /etc/lhy_firewall/log_autosave.fwl";
            system((QString("echo ") + autosave_path + " < /etc/lhy_firewall/gui-autosave").toStdString().c_str());
            autosave_path = "/etc/lhy_firewall/log_autosave";
        }
    }

    QFileInfo inst_file(maninst_path);   // logs for user instructions
    if(!inst_file.exists()){
        system("touch /etc/lhy_firewall/man_log");
    }
    QFile logfile(maninst_path);
    logfile.open(QIODevice::Append | QIODevice::Text);
    logfile.write(sectime_tostring(QDateTime::currentSecsSinceEpoch()).toStdString().c_str());
    logfile.write(", GUI started by user");
    logfile.close();

    for(int i=0; i<HOOK_CNT; i++)
        for(int j=0; j<PROTOCOL_SUPPORTED; j++){
            default_strategy[i][j] = ioctl(devfd, IOCTL_GET_DEFAULT + IOCTL_PROTO(j) + i, 0b10000000);
        }

    nat_model = new QStandardItemModel(nullptr);
    nat_model->setColumnCount(nat_headers.length());
    for(int i=0; i<nat_headers.length(); i++)
        nat_model->setHeaderData(i, Qt::Horizontal, nat_headers.at(i));
    for(int i=0; i<HOOK_CNT; i++)
        for(int j=0; j<PROTOCOL_SUPPORTED; j++){
            rule_models[i][j] = new QStandardItemModel(nullptr);
            rule_models[i][j]->setColumnCount(rule_headers[j].length());
            for(int k=0; k<rule_headers[j].length(); k++)
                rule_models[i][j]->setHeaderData(k, Qt::Horizontal, rule_headers[j].at(k));
        }
    for(int i=0; i<PROTOCOL_SUPPORTED; i++){
        connection_models[i] = new QStandardItemModel(nullptr);
        connection_models[i]->setColumnCount(connection_headers[i].length());
        for(int k=0; k<connection_headers[i].length(); k++)
            connection_models[i]->setHeaderData(k, Qt::Horizontal, connection_headers[i].at(k));
        log_models[i] = new QStandardItemModel(nullptr);
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
    selected_model = connection_models[current_proto];
    initialize_click = false;
    start_update_table(0, 0, 0);

    ui->infotable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->infotable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->infotable->verticalHeader()->hide();
    filter = new log_filter();
}

void Widget::closeEvent(QCloseEvent* e){
    Q_UNUSED(e);
    ::close(devfd);
    update_timer.stop();
    shell("rmmod ../kernel/lhy_firewall.ko", "Successfully removed the kernel module.",
          "Failed to remove the kernel module.");
    exit(0);
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
    ui->infotable->verticalHeader()->hide();
    ui->infotable->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->infotable->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->infotable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->infotable->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->infotable->setSelectionMode(QAbstractItemView::SingleSelection);
}

void Widget::show_row_range(unsigned start, unsigned end){
    for(int i=0; i<start; i++)
        ui->infotable->setRowHidden(i, true);
    for(int i=start; i<end; i++)
        ui->infotable->setRowHidden(i, false);
    for(int i=end; i<selected_model->rowCount(); i++)
        ui->infotable->setRowHidden(i, true);
}

void Widget::update_table(unsigned info, unsigned hook, unsigned proto){
    ui->infotable->setUpdatesEnabled(false);
    switch(info){
    case INFO_CON:
        selected_model = connection_models[proto];
        ui->infotable->setModel(selected_model);
        con_table::update_connections(proto);
        break;
    case INFO_RULE:
        selected_model = rule_models[hook][proto];
        ui->infotable->setModel(selected_model);
        rule_table::update_rules(hook, proto);
        break;
    case INFO_LOG:
        selected_model = log_models[proto];
        ui->infotable->setModel(selected_model);
        log_table::update_log(proto);
        break;
    case INFO_NAT:
        selected_model = nat_model;
        ui->infotable->setModel(nat_model);
        nat_table::update_nat();
        break;
    }
    if((unsigned)selected_model->rowCount() <= rows_per_show)
        ui->view_slider->setEnabled(false);
    else
        ui->view_slider->setEnabled(true);
    ui->view_slider->setMaximum(floor(selected_model->rowCount() * 1.0 / rows_per_show));
    if(log_models[current_proto]->rowCount() < log_length[current_proto])
        show_row_range(ui->view_slider->value() * rows_per_show, (ui->view_slider->value() + 1) * rows_per_show);
    else{
        if(log_model_ptr[current_proto] + ui->view_slider->value() * rows_per_show < log_length[current_proto] &&
           log_model_ptr[current_proto] + (ui->view_slider->value() + 1) * rows_per_show > log_length[current_proto]){
            show_row_range(log_model_ptr[current_proto] + ui->view_slider->value() * rows_per_show, log_length[current_proto]);
            show_row_range(0, log_model_ptr[current_proto] + (ui->view_slider->value() + 1) * rows_per_show - log_length[current_proto]);
        }else{
            show_row_range((log_model_ptr[current_proto] + ui->view_slider->value() * rows_per_show) % log_length[current_proto],
                           (log_model_ptr[current_proto] + (ui->view_slider->value() + 1) * rows_per_show) % log_length[current_proto]);
        }
    }
    ui->infotable->setUpdatesEnabled(true);
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
    for(auto btn: hooks->buttons())
        btn->setEnabled(false);
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_btn_rules_clicked()
{
    current_info = INFO_RULE;
    for(auto btn: hooks->buttons())
        btn->setEnabled(true);
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_btn_logs_clicked()
{
    current_info = INFO_LOG;
    for(auto btn: hooks->buttons())
        btn->setEnabled(false);
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_infotable_customContextMenuRequested(const QPoint &pos)
{
    Q_UNUSED(pos);
//    if(ui->btn_rules->isDown()){
//        QModelIndexList selectedIndexes = ui->infotable->selectionModel()->selectedIndexes();
//        if(selectedIndexes.length() == 0)
//            return;
//        QMenu menu;
//        QAction* del_action = menu.addAction("Delete this rule");
//        connect(del_action, &QAction::triggered, this, [this, selectedIndexes](){
//            for(int i=0; i<selectedIndexes.length(); i++){
//                QModelIndex idx = selectedIndexes[i];
//                rule_tbd tbd = {(unsigned)protos->checkedId(), (unsigned)hooks->checkedId(), (unsigned)idx.row() + 1};
//                rule_deler::del_rule(&tbd);
//            }
//        });
//        menu.exec(QCursor::pos());
//    }
}

void Widget::on_view_slider_valueChanged(int value)
{
    Q_UNUSED(value);
    if(log_models[current_proto]->rowCount() < log_length[current_proto])
        show_row_range(ui->view_slider->value() * rows_per_show, (ui->view_slider->value() + 1) * rows_per_show);
    else{
        if(log_model_ptr[current_proto] + ui->view_slider->value() * rows_per_show < log_length[current_proto] &&
           log_model_ptr[current_proto] + (ui->view_slider->value() + 1) * rows_per_show > log_length[current_proto]){
            show_row_range(log_model_ptr[current_proto] + ui->view_slider->value() * rows_per_show, log_length[current_proto]);
            show_row_range(0, log_model_ptr[current_proto] + (ui->view_slider->value() + 1) * rows_per_show - log_length[current_proto]);
        }else{
            show_row_range((log_model_ptr[current_proto] + ui->view_slider->value() * rows_per_show) % log_length[current_proto],
                           (log_model_ptr[current_proto] + (ui->view_slider->value() + 1) * rows_per_show) % log_length[current_proto]);
        }
    }
    ui->slider_val->setValue(ui->view_slider->value());
}

void Widget::on_view_slider_rangeChanged(int min, int max)
{
    Q_UNUSED(min);
    ui->slider_val->setMaximum(max);
    ui->slider_max->setText(QString::number(max));
}

void Widget::on_slider_val_editingFinished()
{
    ui->view_slider->setValue(ui->slider_val->value());
}

void Widget::on_slider_val_valueChanged(int arg1)
{
    Q_UNUSED(arg1);
    ui->view_slider->setValue(ui->slider_val->value());
}

void Widget::on_btn_clearlog_clicked()
{
    int user_choice =
            QMessageBox::question(this, "note", "This will delete all logs of this protocol, continue?");
    if(user_choice == QMessageBox::No)
        return;
    if(!ioctl(devfd, IOCTL_CLEAR_LOG, current_proto)){
        log_models[current_proto]->clear();
        log_models[current_proto]->setColumnCount(log_headers[current_proto].length());
        for(int k=0; k<log_headers[current_proto].length(); k++)
            log_models[current_proto]->setHeaderData(k, Qt::Horizontal, log_headers[current_proto].at(k));
        log_model_ptr[current_proto] = 0;

        QMessageBox::information(this, "note", "Log cleared.");
    }else{
        QMessageBox::critical(this, "error", "Failed to clear log, unknown error occured.");
    }
}

void Widget::on_btn_addnat_clicked()
{
    nat_adder* wg = new nat_adder(nullptr);
    wg->show();
}

void Widget::on_btn_nats_clicked()
{
    current_info = INFO_NAT;
    start_update_table(current_info, current_hook, current_proto);
}

void Widget::on_btn_logfilter_clicked()
{
    log_filter* filter = new log_filter();
    filter->show();
}

void Widget::on_btn_delnat_clicked()
{
    nat_deler* deler = new nat_deler();
    deler->show();
}
