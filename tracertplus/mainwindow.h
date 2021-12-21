#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QVector>
#include "pcap.h"
#include "readonlydelegate.h"
#include "datapackage.h"
#include "sendicmp.h"
#include "httprequest.h"


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();
    // show network card
    void ShowNetworkCard();
    int Capture();
    QColor SetColor(int type);

private slots:
    void on_comboBox_currentIndexChanged(int index);
    void HandleMessage(DataPackage data);
    void HandleInfo(QString info);
    void HandleAddr(QString addr);
    void on_pushButton_clicked();
    void on_pushButton_2_clicked();
    // query the ip addr [API]
    void on_pushButton_3_clicked();
    // show the detail info about data package
    void on_tableWidget_cellClicked(int row);
    // show ethernet layer
    void ShowEthenet();
    // show ip/arp layer
    void ShowArp();
    int ShowIp();
    // show icmp layer
    void ShowIcmp(int payload);
    // show tcp layer
    void ShowTcp(int payload);
    // show udp layer
    void ShowUdp();

    void on_tableWidget_currentCellChanged(int currentRow,int previousRow);

    void on_lineEdit_4_returnPressed();

private:
    Ui::MainWindow *ui;
    pcap_if_t* all_devices;              // all adapter device
    pcap_if_t* device;                   // an adapter
    pcap_t* pointer;                     // data package pointer
    ReadOnlyDelegate* readonly_delegate; // readonly delegate
    char errbuf[PCAP_ERRBUF_SIZE];       // error buffer
    unsigned char count_number;          // number of package
    QVector<DataPackage> package_data;   // array of package data
    SendIcmp *sender;                    // icmp sender thread
    HttpRequest* http;                   // query the ip addr
    int row_number;                      // widget row number
};
#endif // MAINWINDOW_H
