#include "settings.h"
#include "ui_settings.h"

settings::settings(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::settings)
{
    ui->setupUi(this);
    ui->tcp_syn_timeout->setValue(TCP_syn_timeout);
    ui->tcp_fin_timeout->setValue(TCP_fin_timeout);
    ui->tcp_initial_timeout->setValue(initial_timeout[RULE_TCP]);
    ui->udp_initial_timeout->setValue(initial_timeout[RULE_UDP]);
    ui->icmp_initial_timeout->setValue(initial_timeout[RULE_ICMP]);
    ui->tcp_max_timeout->setValue(connection_max_timeout[RULE_TCP]);
    ui->udp_max_timeout->setValue(connection_max_timeout[RULE_UDP]);
    ui->icmp_max_timeout->setValue(connection_max_timeout[RULE_ICMP]);
    ui->tcp_timeout_fixed->setChecked(TCP_con_timeout_fixed);
    ui->udp_timeout_fixed->setChecked(UDP_con_timeout_fixed);
    ui->tcp_max_con->setValue(max_con[RULE_TCP]);
    ui->udp_max_con->setValue(max_con[RULE_UDP]);
    ui->icmp_max_con->setValue(max_con[RULE_ICMP]);
    ui->tcp_max_logs->setValue(log_length[RULE_TCP]);
    ui->udp_max_logs->setValue(log_length[RULE_UDP]);
    ui->icmp_max_logs->setValue(log_length[RULE_ICMP]);
    ui->max_rule->setValue(max_rule);
    ui->rule_path->setText(rule_path);
    ui->default_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->default_table->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Fixed);
    ui->default_table->horizontalHeader()->resizeSection(0, 180);
    spinbox_maps = {
        {CONF_TCP_SYN_TMO, ui->tcp_syn_timeout},
        {CONF_TCP_FIN_TMO, ui->tcp_fin_timeout},
        {CONF_TCP_INI_TMO, ui->tcp_initial_timeout},
        {CONF_UDP_INI_TMO, ui->udp_initial_timeout},
        {CONF_ICMP_INI_TMO, ui->icmp_initial_timeout},
        {CONF_TCP_MAX_TMO, ui->tcp_max_timeout},
        {CONF_UDP_MAX_TMO, ui->udp_max_timeout},
        {CONF_ICMP_MAX_TMO, ui->icmp_max_timeout},
        {CONF_TCP_MAX_CON, ui->tcp_max_con},
        {CONF_UDP_MAX_CON, ui->udp_max_con},
        {CONF_ICMP_MAX_CON, ui->icmp_max_con},
        {CONF_TCP_MAX_LOG, ui->tcp_max_logs},
        {CONF_UDP_MAX_LOG, ui->udp_max_logs},
        {CONF_ICMP_MAX_LOG, ui->icmp_max_logs},
        {CONF_MAX_RULE, ui->max_rule},
    };
    checkbox_maps = {
        {CONF_TCP_FIX_TMO, ui->tcp_timeout_fixed},
        {CONF_UDP_FIX_TMO, ui->udp_timeout_fixed},
    };
    ui->default_table->setColumnCount(DEFAULT_OPTIONS + 2);
    ui->default_table->setRowCount(PROTOCOL_SUPPORTED * HOOK_CNT);
    QStringList table_headers;
    ui->default_table->setHorizontalHeaderLabels(table_headers);
    for(int i=0; i<PROTOCOL_SUPPORTED * HOOK_CNT; i+=PROTOCOL_SUPPORTED){
        ui->default_table->setSpan(i, 0, 3, 1);
        for(int j=0; j<PROTOCOL_SUPPORTED; j++){
            QCheckBox* cb1 = new QCheckBox(this);
            cb1->setChecked(default_strategy[i/3][j] & 1);
            connect(cb1, &QCheckBox::stateChanged, this, [cb1, i, j](){
                if(set_default_strategy(i/3, j, 0, cb1->isChecked()))
                    default_strategy[i/3][j] |= cb1->isChecked() << 0;
                cb1->setText(cb1->isChecked() ? "Accept" : "Reject");
            });
            emit cb1->stateChanged(cb1->isChecked());
            ui->default_table->setCellWidget(i + j, 2, cb1);

            QCheckBox* cb2 = new QCheckBox(this);
            cb2->setChecked(default_strategy[i/3][j] & 2);
            connect(cb2, &QCheckBox::stateChanged, this, [cb2, i, j](){
                if(set_default_strategy(i/3, j, 1, cb2->isChecked()))
                    default_strategy[i/3][j] |= cb2->isChecked() << 1;
                cb2->setText(cb2->isChecked() ? "Log   " : "No Log");
            });
            emit cb2->stateChanged(cb2->isChecked());
            ui->default_table->setCellWidget(i + j, 3, cb2);
        }
    }
}

settings::~settings()
{
    delete ui;
}

bool settings::set_config(unsigned cid, unsigned val){
    if(spinbox_maps.find(cid) == spinbox_maps.end())
        return false;
    config_user c = {cid, val};
    if(ioctl(devfd, IOCTL_SET_CONFIG, &c))
        QMessageBox::critical(this, "config failed to set", "Failed to set TCP SYN timeout.");
    else if((unsigned)ioctl(devfd, IOCTL_GET_CONFIG, cid) != val)
        QMessageBox::critical(this, "config set error", "A different value received from kernel, there may be a bug!");
    spinbox_maps[cid]->setValue(ioctl(devfd, IOCTL_GET_CONFIG, cid));
    *configs[cid] = ioctl(devfd, IOCTL_GET_CONFIG, cid);
    return true;
}

bool settings::set_config(unsigned cid, bool checked){
    if(checkbox_maps.find(cid) == checkbox_maps.end())
        return false;
    config_user c = {cid, checked};
    if(ioctl(devfd, IOCTL_SET_CONFIG, &c))
        QMessageBox::critical(this, "config failed to set", "Failed to set TCP SYN timeout.");
    else if(ioctl(devfd, IOCTL_GET_CONFIG, cid) != checked)
        QMessageBox::critical(this, "config set error", "A different value received from kernel, there may be a bug!");
    checkbox_maps[cid]->setChecked(ioctl(devfd, IOCTL_GET_CONFIG, cid));
    return true;
}

bool settings::set_config(QString filepath){
    if(ioctl(devfd, IOCTL_SET_RULE_PATH, filepath.toStdString().c_str())){
        QMessageBox::critical(this, "rule path failed to set", "Failed to set rule path, check your path first.");
        return false;
    }
    return true;
}

void settings::on_tcp_timeout_fixed_stateChanged(int arg1)
{
    set_config(CONF_TCP_FIX_TMO, arg1 == Qt::Checked);
}

void settings::on_udp_timeout_fixed_stateChanged(int arg1)
{
    set_config(CONF_UDP_FIX_TMO, arg1 == Qt::Checked);
}

void settings::on_rule_path_editingFinished()
{
    QString path = ui->rule_path->text();
    QFileInfo fileinfo(path);
    QString parentDir = fileinfo.path();
    QFileInfo parentDirInfo(parentDir);
    QDir directory(parentDir);
    if(!parentDirInfo.isDir()){
        QMessageBox::warning(this, "input format error", "The input's parent directory not found! "
                                                         "Please input absolute path and confirm that the path exists.");
        return;
    }
    if(!directory.isAbsolute()){
        QMessageBox::warning(this, "input format error", "Please input absolute path!");
        return;
    }
    if(fileinfo.exists()){
        if(fileinfo.isFile())
            set_config(path);
        else{
            QMessageBox::warning(this, "input error", "Input is a directory, not a file.");
            ui->rule_path->setText(rule_path);
        }
    }else
        set_config(path);
}

void settings::on_tcp_syn_timeout_editingFinished()
{
    set_config(CONF_TCP_SYN_TMO, (unsigned)spinbox_maps[CONF_TCP_SYN_TMO]->value());
}

void settings::on_tcp_fin_timeout_editingFinished()
{
    set_config(CONF_TCP_FIN_TMO, (unsigned)spinbox_maps[CONF_TCP_FIN_TMO]->value());
}

void settings::on_tcp_initial_timeout_editingFinished()
{
    set_config(CONF_TCP_INI_TMO, (unsigned)spinbox_maps[CONF_TCP_INI_TMO]->value());
}

void settings::on_udp_initial_timeout_editingFinished()
{
    set_config(CONF_UDP_INI_TMO, (unsigned)spinbox_maps[CONF_UDP_INI_TMO]->value());
}

void settings::on_icmp_initial_timeout_editingFinished()
{
    set_config(CONF_ICMP_INI_TMO, (unsigned)spinbox_maps[CONF_ICMP_INI_TMO]->value());
}

void settings::on_tcp_max_timeout_editingFinished()
{
    set_config(CONF_TCP_MAX_TMO, (unsigned)spinbox_maps[CONF_TCP_MAX_TMO]->value());
}

void settings::on_udp_max_timeout_editingFinished()
{
    set_config(CONF_UDP_MAX_TMO, (unsigned)spinbox_maps[CONF_UDP_MAX_TMO]->value());
}

void settings::on_icmp_max_timeout_editingFinished()
{
    set_config(CONF_ICMP_MAX_TMO, (unsigned)spinbox_maps[CONF_ICMP_MAX_TMO]->value());
}

void settings::on_tcp_max_con_editingFinished()
{
    set_config(CONF_TCP_MAX_CON, (unsigned)spinbox_maps[CONF_TCP_MAX_CON]->value());
}

void settings::on_udp_max_con_editingFinished()
{
    set_config(CONF_UDP_MAX_CON, (unsigned)spinbox_maps[CONF_UDP_MAX_CON]->value());
}

void settings::on_icmp_max_con_editingFinished()
{
    set_config(CONF_ICMP_MAX_CON, (unsigned)spinbox_maps[CONF_ICMP_MAX_CON]->value());
}

void settings::on_tcp_max_logs_editingFinished()
{
    set_config(CONF_TCP_MAX_LOG, (unsigned)spinbox_maps[CONF_TCP_MAX_LOG]->value());
}

void settings::on_udp_max_logs_editingFinished()
{
    set_config(CONF_UDP_MAX_LOG, (unsigned)spinbox_maps[CONF_UDP_MAX_LOG]->value());
}

void settings::on_icmp_max_logs_editingFinished()
{
    set_config(CONF_ICMP_MAX_LOG, (unsigned)spinbox_maps[CONF_ICMP_MAX_LOG]->value());
}

void settings::on_max_rule_editingFinished()
{
    set_config(ui->rule_path->text());
}

void settings::on_btn_savelog_clicked()
{
    QString savepath = QFileDialog::getSaveFileName(this, "Select file", QDir::homePath(), "Firewall Log File (*.fwl)");
    if(savepath.isEmpty())
        return;
    QFileInfo fileInfo(savepath);
    QFile file(savepath);
    if(fileInfo.exists()){
        int user_choice =
                QMessageBox::question(this, "file exists", "Using this file will lost its original content, continue?");
        if(user_choice == QMessageBox::No)
            return;
        if(file.open(QIODevice::WriteOnly | QIODevice::Truncate))
            file.close();
        else{
            QMessageBox::critical(this, "IO error", "Failed to truncate the file.");
            return;
        }
    }else if(!QDir(fileInfo.path()).exists()){
        QMessageBox::warning(this, "path not found", "The path of this file didn't exist.");
        return;
    }
    ioctl(devfd, IOCTL_WRITE_LOG, savepath);
    QMessageBox::information(this, "log saved", "Log already saved into " + savepath + ".");
}

void settings::on_log_autosave_stateChanged(int arg1)
{
    Q_UNUSED(arg1);
    autosave_log = ui->log_autosave->isChecked();
    if(!autosave_log)
        ui->log_path->setEnabled(false);
}
