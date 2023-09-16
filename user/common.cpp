#include "common.h"

QStandardItemModel* connection_models[PROTOCOL_SUPPORTED];
QStandardItemModel* rule_models[HOOK_CNT][PROTOCOL_SUPPORTED];
QStandardItemModel* log_models[PROTOCOL_SUPPORTED];
unsigned log_model_ptr[PROTOCOL_SUPPORTED] = {0, 0, 0};     // represents the index of the earlist record
int devfd;
int frontend_update_interval = 1000;    //msec

// configs
unsigned TCP_syn_timeout;                                    // config code = 0
unsigned TCP_fin_timeout;                                    // 1
unsigned initial_timeout[PROTOCOL_SUPPORTED];                // 2-4
unsigned connection_max_timeout[PROTOCOL_SUPPORTED];         // 5-7
unsigned TCP_con_timeout_fixed;                              // 8
unsigned UDP_con_timeout_fixed;                              // 9
unsigned max_con[PROTOCOL_SUPPORTED];                        // 10-12
unsigned log_length[PROTOCOL_SUPPORTED];                     // 13-15
unsigned max_rule;
char rule_path[256];
unsigned default_strategy[HOOK_CNT][PROTOCOL_SUPPORTED];
unsigned rows_per_show = 20;
bool autosave_log = true;   // save log through GUI, not kernel
QString autosave_path = "/etc/lhy_firewall/log_autosave";   // a directory

const QString hook_names[HOOK_CNT] = {
    "PRE_ROUTING",
    "LOCAL_IN",
    "LOCAL_OUT",
    "FORWARD",
    "POST_ROUTING"
};

const QString proto_names[PROTOCOL_SUPPORTED] = {
    "TCP", "UDP", "ICMP"
};

unsigned* configs[CONFIG_CNT] = {
    &TCP_syn_timeout,
    &TCP_fin_timeout,
    &initial_timeout[0],
    &initial_timeout[1],
    &initial_timeout[2],
    &connection_max_timeout[0],
    &connection_max_timeout[1],
    &connection_max_timeout[2],
    &TCP_con_timeout_fixed,
    &UDP_con_timeout_fixed,
    &max_con[0],
    &max_con[1],
    &max_con[2],
    &log_length[0],
    &log_length[1],
    &log_length[2],
    &max_rule
};

void print_binary(char* buf, int length){
    qDebug() << "---------------------------------------------------------------------------";
    char output_buffer[80];
    sprintf(output_buffer, "Address info starting in %p:", buf);
    qDebug() << output_buffer;
    int index = 0;
    memset(output_buffer, '\0', 80);
    memset(output_buffer, ' ', 0x10);
    for(int i=0; i<(length % 16 == 0 ? length / 16 : length / 16 + 1); i++){
        char temp_buffer[0x10];
        memset(temp_buffer, '\0', 0x10);
        sprintf(temp_buffer, "%#5x", index);
        strcpy(output_buffer, temp_buffer);
        output_buffer[5] = ' ';
        output_buffer[6] = '|';
        output_buffer[7] = ' ';
        for(int j=0; j<16; j++){
            if(index+j >= length)
                sprintf(output_buffer+8+3*j, "   ");
            else{
                sprintf(output_buffer+8+3*j, "%02x ", ((int)buf[index+j]) & 0xFF);
                if(!isprint(buf[index+j]))
                    output_buffer[58+j] = '.';
                else
                    output_buffer[58+j] = buf[index+j];
            }
        }
        output_buffer[55] = ' ';
        output_buffer[56] = '|';
        output_buffer[57] = ' ';
        qDebug() << output_buffer;
        memset(output_buffer+58, '\0', 16);
        index += 16;
    }
    qDebug() << "---------------------------------------------------------------------------";
}

bool set_default_strategy(unsigned hook, unsigned proto, unsigned bit, bool val){
    if(ioctl(devfd, IOCTL_SET_DEFAULT | IOCTL_PROTO(proto) | hook, SET_DEFAULT(hook, proto, bit, val))){
        QMessageBox::warning(nullptr, "error", "Failed to set default strategy for unknown reason. There may be bugs!");
        return false;
    }
    return true;
}

QString usectime_tostring(unsigned long long time){
    QDateTime datetime;
    datetime.setSecsSinceEpoch(time / 1000000);
    QString ret = QString("%1/%2/%3 %4:%5:%6.%7")
            .arg(datetime.date().year(), 4, 10, QLatin1Char('0'))
            .arg(datetime.date().month(), 2, 10, QLatin1Char('0'))
            .arg(datetime.date().day(), 2, 10, QLatin1Char('0'))
            .arg(datetime.time().hour(), 2, 10, QLatin1Char('0'))
            .arg(datetime.time().minute(), 2, 10, QLatin1Char('0'))
            .arg(datetime.time().second(), 2, 10, QLatin1Char('0'))
            .arg(time % 1000000, 6, 10, QLatin1Char('0'));
    return ret;
}

QString sectime_tostring(unsigned long long time){
    QDateTime datetime;
    datetime.setSecsSinceEpoch(time);
    QString ret = QString("%1/%2/%3 %4:%5:%6")
            .arg(datetime.date().year(), 4, 10, QLatin1Char('0'))
            .arg(datetime.date().month(), 2, 10, QLatin1Char('0'))
            .arg(datetime.date().day(), 2, 10, QLatin1Char('0'))
            .arg(datetime.time().hour(), 2, 10, QLatin1Char('0'))
            .arg(datetime.time().minute(), 2, 10, QLatin1Char('0'))
            .arg(datetime.time().second(), 2, 10, QLatin1Char('0'));
    return ret;
}

int shell(QString command, QString success_message, QString fail_message){
    QProcess process;
    process.start(command);
    if(process.waitForStarted() && process.waitForFinished()){
        QByteArray output = process.readAllStandardOutput();
        QString outputString(output);
        qDebug() << "Command output: " + outputString;
        int exitCode = process.exitCode();
        qDebug() << "Process " + command + " returns " + QString::number(exitCode);
        if(exitCode == 0)
            qDebug() << success_message;
        else
            qDebug() << fail_message;
        return exitCode;
    }else{
        qDebug() << fail_message;
        return -1;
    }
}

bool save_file_valid(QString path){
    QFileInfo fi(path);
    if(fi.exists())
        return true;
    if(!QDir::isAbsolutePath(path))
        return false;
    QStringList paths = path.split("/");
    paths.removeLast();
    QString parent_path = paths.join("/");
    return QFileInfo(parent_path).exists();
}

QString readall(QString path){
    QFile file(path);
    if(file.open(QIODevice::ReadOnly | QIODevice::Text)){
        QTextStream stream(&file);
        QString content = stream.readAll();
        file.close();
        return content;
    }else{
        qDebug() << "Failed to open" << path.toStdString().c_str();
        return "";
    }
}
