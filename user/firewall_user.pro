QT       += core gui

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets network

CONFIG += c++11

# The following define makes your compiler emit warnings if you use
# any Qt feature that has been marked deprecated (the exact warnings
# depend on your compiler). Please consult the documentation of the
# deprecated API in order to know how to port your code away from it.
DEFINES += QT_DEPRECATED_WARNINGS

# You can also make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
# You can also select to disable deprecated APIs only up to a certain version of Qt.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    common.cpp \
    con_table.cpp \
    filter_widget.cpp \
    log_filter.cpp \
    log_table.cpp \
    main.cpp \
    nat_adder.cpp \
    nat_deler.cpp \
    nat_table.cpp \
    rule_adder.cpp \
    rule_changer.cpp \
    rule_deler.cpp \
    rule_table.cpp \
    settings.cpp \
    widget.cpp

HEADERS += \
    common.h \
    con_table.h \
    filter_widget.h \
    log_filter.h \
    log_table.h \
    nat_adder.h \
    nat_deler.h \
    nat_table.h \
    rule_adder.h \
    rule_changer.h \
    rule_deler.h \
    rule_table.h \
    settings.h \
    widget.h

FORMS += \
    filter_widget.ui \
    log_filter.ui \
    nat_adder.ui \
    nat_deler.ui \
    rule_adder.ui \
    rule_changer.ui \
    rule_deler.ui \
    settings.ui \
    widget.ui

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
