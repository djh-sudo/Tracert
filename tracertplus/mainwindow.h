#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QVector>
#include <QTimer>
#include "pcap.h"
#include "readonlydelegate.h"
#include "datapackage.h"
#include "sendicmp.h"
#include "httprequest.h"
#include "subthread.h"

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
    void HidePackage(unsigned int number);

private slots:
    void on_comboBox_currentIndexChanged(int index);
    void HandleMessage(DataPackage data);
    void HandleInfo(QString info);
    void HandleAddr(QString addr);


    void ShowEthenet();         // show ethernet layer
    void ShowArp();             // show arp layer
    int ShowIp();               // show ip layer
    void ShowIcmp(int payload); // show icmp layer
    void ShowTcp(int payload);  // show tcp layer
    void ShowUdp();             // show udp layer
    void Timeout();             // every 1 second update time and info
    //use keyboard to control
    void on_tableWidget_currentCellChanged(int currentRow,int previousRow);
    // query ip position
    void on_lineEdit_4_returnPressed();
    // show icmp package only
    void on_checkBox_stateChanged();
    // query the ip addr [API]
    void on_pushButton_3_clicked();
    // show the detail info about data package
    void on_tableWidget_cellClicked(int row);
    // start tracert
    void on_pushButton_clicked();
    // stop tracert
    void on_pushButton_2_clicked();

private:
    Ui::MainWindow *ui;
    pcap_if_t* all_devices;              // all adapter device
    pcap_if_t* device;                   // an adapter
    pcap_t* pointer;                     // data package pointer
    ReadOnlyDelegate* readonly_delegate; // readonly delegate
    char errbuf[PCAP_ERRBUF_SIZE];       // error buffer
    unsigned int count_number;           // number of package
    QVector<DataPackage> package_data;   // array of package data
    SendIcmp* sender;                    // icmp sender thread
    HttpRequest* http;                   // query the ip addr
    SubThread* thread;                   // icmp ping thread
    QTimer* timer;                       // timer
    int row_number;                      // widget row number
    bool is_start;                       // flag of start
    bool is_hidden;                      // hide the other packge
};
#endif // MAINWINDOW_H
