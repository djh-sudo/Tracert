#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QAbstractItemView>
#include <QStringList>
#include <QString>
#include <QColor>
#include <QTextCodec>
#include <QRegExp>
#include <QDebug>
#include "subthread.h"


MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    // GUI initial
    this->readonly_delegate = new ReadOnlyDelegate();

    ui->textEdit->clear();
    ui->tableWidget->setItemDelegate(readonly_delegate);
    ui->tableWidget->setShowGrid(false);
    ui->tableWidget->setColumnCount(7);
    ui->tableWidget->verticalHeader()->setVisible(false);
    QStringList title = {"NO.","Time","Source","Destination","Protocol","Length","Info"};
    ui->tableWidget->setHorizontalHeaderLabels(title);

    ui->tableWidget->verticalHeader()->setDefaultSectionSize(30);
    ui->tableWidget->setColumnWidth(0,50);
    ui->tableWidget->setColumnWidth(1,150);
    ui->tableWidget->setColumnWidth(2,300);
    ui->tableWidget->setColumnWidth(3,300);
    ui->tableWidget->setColumnWidth(4,100);
    ui->tableWidget->setColumnWidth(5,100);
    ui->tableWidget->setColumnWidth(6,900);
    ui->tableWidget->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->treeWidget->setHeaderHidden(true);

    // set default name
    ui->lineEdit->setText(TRACE_EXAMPLE);
    ui->lineEdit_2->setText(QString::number(ICMP_MAX_HOP));
    ui->lineEdit_3->setText(QString::number(ICMP_MAX_TIMEOUT));
    ui->lineEdit_6->setText(QString(PADDING_LETTER));
    ui->comboBox->setEnabled(true);

    // add toolbar
    ui->toolBar->addAction(ui->actionrun);
    ui->toolBar->addAction(ui->actionclear_box);

    // other initical
    this->device = nullptr;
    this->all_devices = nullptr;
    this->pointer = nullptr;
    this->row_number = -1;
    this->package_data.clear();

    static bool action_index = false;
    // show network card!
    ShowNetworkCard();

    // create a sub thread
    SubThread* thread = new SubThread;
    sender = new SendIcmp;
    http = new HttpRequest;
    // add the signal-slot
    connect(ui->actionrun,&QAction::triggered,this,[=]{
        action_index = !action_index;
        if(action_index){
            // TODO ...
            // initialize the GUI
            ui->tableWidget->clearContents();
            ui->tableWidget->setRowCount(0);
            count_number = 0;
            // memory release
            int package_data_size = package_data.size();
            for(int i = 0; i < package_data_size; i++){
                free((char*)(package_data[i].pkt_content));
                package_data[i].pkt_content = nullptr;
            }
            QVector<DataPackage>().swap(package_data);
            // memory free end
            int result = Capture();
            if(pointer && result != -1){
                count_number = 0;
                bool set_ok = thread->SetPointer(pointer);
                // begin the thread
                if(set_ok){
                    ui->actionrun->setIcon(QIcon(":/stop.png"));
                    ui->comboBox->setEnabled(false);
                    thread->ResetFlag();
                    thread->start();
                }else{
                    // fail to start!
                    action_index = ! action_index;
                    count_number = 0;
                }
            }else{
                // fail to start!
                action_index = ! action_index;
                count_number = 0;

            }
        }else{
            // stop the thread!
            ui->actionrun->setIcon(QIcon(":/start.png"));
            ui->comboBox->setEnabled(true);
            thread->SetFlag();
            thread->quit();
            thread->wait();
        }
    });

    // connect the signal and slot [empty the box]
    connect(ui->actionclear_box,&QAction::triggered,this,[=]{
        ui->textEdit->clear();
    });
    // connect the signal and slot [package recv and show]
    connect(thread,&SubThread::send,this,&MainWindow::HandleMessage);
    // connect the signal and slot [icmp send]
    connect(sender,&SendIcmp::send,this,&MainWindow::HandleInfo);
    // connect the signal and slot [http GET]
    connect(http,&HttpRequest::query,this,&MainWindow::HandleAddr);

}

/*
  * ~ destructor
*/
MainWindow::~MainWindow()
{
    delete ui;
    delete sender;
    if(pointer){
        pcap_close(pointer);
        pointer = nullptr;
    }
    if(all_devices){
        pcap_freealldevs(all_devices);
        all_devices = nullptr;
        device = nullptr;
    }
}

/*
  * show network card
  * scan the network cards and show information about it at combox
*/
void MainWindow::ShowNetworkCard(){
    int n = pcap_findalldevs(&all_devices,errbuf);
    ui->comboBox->clear();
    if(n == -1){
        statusBar()->showMessage("Something wrong" + QString(errbuf));
        ui->comboBox->addItem("Can't find a network card,please restart!");
        all_devices = nullptr;
        return;
    }
    ui->comboBox->clear();
    ui->comboBox->addItem("please chose the network card!");
    for(device = all_devices; device != nullptr; device = device->next){
        QString device_name = device->name;
        device_name.replace("\\Device\\","");
        QString description = device->description;
        QString item = device_name + "  " + description;
        ui->comboBox->addItem(item);

    }
    return;
}

/*
 * on_comboBox_currentIndexChanged
 * when item of combox changed,the device pointer will also change
 * this function could ensure device pointer point to the selected network card
*/
void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    int i = 0;
    if(index != 0){
        for(device = all_devices; i < index - 1; i++,device = device->next);
    }
    return;
}

/*
 * Capture
 * starting capture the package_data package from card
 * the package_data package in package_data link layer must meet the IEEE 802.3 protocol
 * or it will be throwed away
*/
int MainWindow::Capture(){
    if(device){
        pointer = pcap_open_live(device->name,65536,1,1000,errbuf);
    }else{
        statusBar()->showMessage("pls choose network card!");
        return -1;
    }
    // pointer is empty
    if(!pointer){
        statusBar()->showMessage(errbuf);
        pcap_freealldevs(all_devices);
        device = nullptr;
        pointer = nullptr;
        return -1;
    }else{
        // package_data link is IEEE 802.3
        if(pcap_datalink(pointer) != DLT_EN10MB){
            pcap_close(pointer);
            pcap_freealldevs(all_devices);
            device = nullptr;
            pointer = nullptr;
            return -1;
        }else{
            statusBar()->showMessage(device->name);
        }
    }
    return 0;
}

/*
 * [slot] function
 * show message in the table widget
*/
void MainWindow::HandleMessage(DataPackage data){
    ui->tableWidget->insertRow(count_number);
    this->package_data.push_back(data);
    int type = data.GetPackageType();
    QColor color = SetColor(type);
    ui->tableWidget->setItem(count_number,0,new QTableWidgetItem(QString::number(count_number + 1)));
    ui->tableWidget->setItem(count_number,1,new QTableWidgetItem(data.GetTimeStamp()));
    ui->tableWidget->setItem(count_number,2,new QTableWidgetItem(data.GetSource()));
    ui->tableWidget->setItem(count_number,3,new QTableWidgetItem(data.GetDestination()));
    ui->tableWidget->setItem(count_number,4,new QTableWidgetItem(data.GetType()));
    ui->tableWidget->setItem(count_number,5,new QTableWidgetItem(data.GetDataLength()));
    ui->tableWidget->setItem(count_number,6,new QTableWidgetItem(data.GetInfo()));
    for(int i = 0;i < 7;i++){
        ui->tableWidget->item(count_number,i)->setBackground(color);
    }
    count_number++;
}

/*
  * start the tracert
  * start the sub thread
*/
void MainWindow::on_pushButton_clicked()
{
    if(!sender->isRunning()){
        ui->textEdit->clear();
        QString ip_name = ui->lineEdit->text();
        QString max_hop = ui->lineEdit_2->text();
        QString timeout = ui->lineEdit_3->text();
        QString padding = ui->lineEdit_6->text();
        // setting the parameter
        sender->SetIpName(ip_name);
        sender->SetMaxhop(max_hop.toUtf8().toInt());
        sender->SetTimeout(timeout.toUtf8().toInt());
        sender->SetPadding(padding);
        // start the sub thread
        sender->start();
    }else{
        // restart the thread
    }
}

/*
 * receive the info from the icmp sender
 * this info will show at buttom box
*/
void MainWindow::HandleInfo(QString info){
    ui->textEdit->append(info);
}

/*
 * set color of the package
*/

QColor MainWindow::SetColor(int type){
    QColor color = QColor(255,255,224);
    switch (type) {
    case 0: color = QColor(210,149,210);break;
    case 3:
    case 11:color = QColor(144,238,144);break;
    case 20:color = QColor(147,112,219);break; // TCP
    case 21:color = QColor(135,206,250);break; // UDP
    case 22:color = QColor(255,182,193);break; // ARP
    default:break;
    }
    return color;
}

/*
 * stop tracert!
 * kill the thread
*/
void MainWindow::on_pushButton_2_clicked()
{
    if(sender->isRunning()){
        sender->SetKillSig();
        sender->quit();
        sender->wait();
    }
    else
        return;
}

/*
 * query the ip address
 * using [http://ip.ws.126.net/ipquery] API
 * http -> GET to query
*/
void MainWindow::on_pushButton_3_clicked()
{
    QString ip_addr =  ui->lineEdit_4->text();
    http->SetIpAddr(ip_addr);
    if(!http->isRunning())
        http->start();
}

void MainWindow::HandleAddr(QString addr){
    if(addr.length() <= 20)
        ui->lineEdit_5->setText(addr);
    else
        ui->lineEdit_5->setText("try again!");
}

void MainWindow::on_tableWidget_cellClicked(int row)
{
    if(row == row_number || row < 0){
        return;
    }else{
        ui->treeWidget->clear();
        row_number = row;
        if(row_number > package_data.size()) return;
        ShowEthenet();
        int package_type = package_data[row].GetPackageType();
        if(package_type == 22){
            // arp
            ShowArp();
        }
        else{
            // ip
            int payload = ShowIp();
            if(package_type != 20 && package_type != 21)
                ShowIcmp(payload);
            else if(package_type == 20)
                ShowTcp(payload);
            else if(package_type == 21)
                ShowUdp();
            else return;
        }
    }
}

void MainWindow::ShowEthenet(){
    QString desMac = package_data[row_number].GetDesMacAddr();
    QString srcMac = package_data[row_number].GetSrcMacAddr();
    QString type = package_data[row_number].GetMacType();
    QString tree = "Ethernet, Src:" +srcMac + ", Dst:" + desMac;
    QTreeWidgetItem*item = new QTreeWidgetItem(QStringList()<<tree);
    ui->treeWidget->addTopLevelItem(item);

    item->addChild(new QTreeWidgetItem(QStringList()<<"Destination:" + desMac));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Source:" + srcMac));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Type:" + type));

}

void MainWindow::ShowArp(){
    QString ArpType = package_data[row_number].GetArpOpCode();
    QTreeWidgetItem*item = new QTreeWidgetItem(QStringList()<<"Address Resolution Protocol " + ArpType);
    ui->treeWidget->addTopLevelItem(item);
    QString HardwareType = package_data[row_number].GetArpHardwareType();
    QString protocolType = package_data[row_number].GetArpProtocolType();
    QString HardwareSize = package_data[row_number].GetArpHardwareLen();
    QString protocolSize = package_data[row_number].GetArpProtocolLen();
    QString srcMacAddr = package_data[row_number].GetArpSrcEtherAddr();
    QString desMacAddr = package_data[row_number].GetArpDesEtherAddr();
    QString srcIpAddr =  package_data[row_number].GetArpSrcIpAddr();
    QString desIpAddr =  package_data[row_number].GetArpDesIpAddr();

    item->addChild(new QTreeWidgetItem(QStringList() << "Hardware type:" + HardwareType));
    item->addChild(new QTreeWidgetItem(QStringList() << "Protocol type:" + protocolType));
    item->addChild(new QTreeWidgetItem(QStringList() << "Hardware size:" + HardwareSize));
    item->addChild(new QTreeWidgetItem(QStringList() << "Protocol size:" + protocolSize));
    item->addChild(new QTreeWidgetItem(QStringList() << "Opcode:" + ArpType));
    item->addChild(new QTreeWidgetItem(QStringList() << "Sender MAC address:" + srcMacAddr));
    item->addChild(new QTreeWidgetItem(QStringList() << "Sender IP address:" + srcIpAddr));
    item->addChild(new QTreeWidgetItem(QStringList() << "Target MAC address:" + desMacAddr));
    item->addChild(new QTreeWidgetItem(QStringList() << "Target IP address:" + desIpAddr));
    return;
}

int MainWindow::ShowIp(){
    QString srcIp = package_data[row_number].GetSrcIpAddr();
    QString desIp = package_data[row_number].GetDesIpAddr();

    QTreeWidgetItem*item = new QTreeWidgetItem(
                QStringList() << "Internet Protocol Version 4, Src:"
                + srcIp
                + ", Dst:"
                + desIp);
    ui->treeWidget->addTopLevelItem(item);

    QString version = package_data[row_number].GetIpVersion();
    QString headerLength = package_data[row_number].GetIpHeaderLength();
    QString Tos = package_data[row_number].GetIpTos();
    QString totalLength = package_data[row_number].GetIpTotalLength();
    QString id = "0x" + package_data[row_number].GetIpIdentification();
    QString flags = package_data[row_number].GetIpFlag();
    if(flags.size() < 2)
        flags = "0" + flags;
    flags = "0x" + flags;
    QString FragmentOffset = package_data[row_number].GetIpFragmentOffset();
    QString ttl = package_data[row_number].GetIpTTL();
    QString protocol = package_data[row_number].GetIpProtocol();
    QString checksum = "0x" + package_data[row_number].GetIpCheckSum();

    item->addChild(new QTreeWidgetItem(QStringList() << "0100 .... = Version:" + version));
    item->addChild(new QTreeWidgetItem(QStringList() << ".... 0101 = Header Length:" + headerLength));
    item->addChild(new QTreeWidgetItem(QStringList() << "TOS:" + Tos));
    item->addChild(new QTreeWidgetItem(QStringList() << "Total Length:" + totalLength));
    item->addChild(new QTreeWidgetItem(QStringList() << "Identification:" + id));

    QString reservedBit = package_data[row_number].GetIpReservedBit();
    QString DF = package_data[row_number].GetIpDF();
    QString MF = package_data[row_number].GetIpMF();
    QString FLAG = ",";

    if(reservedBit == "1"){
        FLAG += "Reserved bit";
    }
    else if(DF == "1"){
        FLAG += "Don't fragment";
    }
    else if(MF == "1"){
        FLAG += "More fragment";
    }
    if(FLAG.size() == 1)
        FLAG = "";
    QTreeWidgetItem*bitTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flags + FLAG);
    item->addChild(bitTree);
    QString temp = reservedBit == "1"?"Set":"Not set";
    bitTree->addChild(new QTreeWidgetItem(QStringList() << reservedBit + "... .... = Reserved bit:" + temp));
    temp = DF == "1" ? "Set":"Not set";
    bitTree->addChild(new QTreeWidgetItem(QStringList()<<"." + DF + ".. .... = Don't fragment:" + temp));
    temp = MF == "1" ? "Set":"Not set";
    bitTree->addChild(new QTreeWidgetItem(QStringList()<<".." + MF + ". .... = More fragment:" + temp));

    item->addChild(new QTreeWidgetItem(QStringList() << "Fragment Offset:" + FragmentOffset));
    item->addChild(new QTreeWidgetItem(QStringList() << "Time to Live:" + ttl));
    item->addChild(new QTreeWidgetItem(QStringList() << "Protocol:" + protocol));
    item->addChild(new QTreeWidgetItem(QStringList() << "Header checksum:" + checksum));
    item->addChild(new QTreeWidgetItem(QStringList() << "Source Address:" + srcIp));
    item->addChild(new QTreeWidgetItem(QStringList() << "Destination Address:" + desIp));
    return totalLength.toUtf8().toInt() - 20;
}

void MainWindow::ShowIcmp(int payload){
    payload -= 8;
    QTreeWidgetItem*item = new QTreeWidgetItem(QStringList()<<"Internet Message Protocol");
    ui->treeWidget->addTopLevelItem(item);
    QString type = package_data[row_number].GetIcmpType();
    QString code = package_data[row_number].GetIcmpCode();
    QString info = ui->tableWidget->item(row_number,6)->text();
    QString checksum = "0x" + package_data[row_number].GetIcmpCheckSum();
    QString id = package_data[row_number].GetIcmpIdentification();
    QString seq = package_data[row_number].GetIcmpSequeue();
    item->addChild(new QTreeWidgetItem(QStringList()<<"type:" + type + "(" + info + ")"));
    item->addChild(new QTreeWidgetItem(QStringList()<<"code:" + code));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:" + checksum));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Identifier:" + id));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number:" + seq));
    int code_type = package_data[row_number].GetPackageType();
    if(payload > 0){
        QTreeWidgetItem* dataItem = new QTreeWidgetItem(QStringList()<<"Data (" + QString::number(payload) + ") bytes");
        item->addChild(dataItem);
        if(code_type != 11){
            QString icmpData = package_data[row_number].GetIcmpData(payload);
            dataItem->addChild(new QTreeWidgetItem(QStringList()<<icmpData));
        }
        else{
        }
    }
}

void MainWindow::ShowTcp(int payload){
    QString desPort = package_data[row_number].GetTcpDesPort();
    QString srcPort = package_data[row_number].GetTcpSrcPort();
    QString ack = package_data[row_number].GetTcpAck();
    QString seq = package_data[row_number].GetTcpSequence();
    QString headerLength = package_data[row_number].GetTcpHeaderLen();
    int rawLength = package_data[row_number].GetTcpRawHeaderLen().toUtf8().toInt();
    payload -= (rawLength * 4);
    QString dataLength = QString::number(payload);
    QString flag = package_data[row_number].GetTcpFlags();
    while(flag.size() < 2)
        flag = "0" + flag;
    flag = "0x" + flag;
    QTreeWidgetItem* item = new QTreeWidgetItem(QStringList()<<"Transmission Control Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort + ",Seq:" + seq + ", Ack:" + ack + ", Len:" + dataLength);

    ui->treeWidget->addTopLevelItem(item);
    item->addChild(new QTreeWidgetItem(QStringList() << "Source Port:" + srcPort));
    item->addChild(new QTreeWidgetItem(QStringList() << "Destination Port:" + desPort));
    item->addChild(new QTreeWidgetItem(QStringList() << "Sequence Number (raw) :" + seq));
    item->addChild(new QTreeWidgetItem(QStringList() << "Ackowledgment Number (raw) :" + ack));


    QString sLength = QString::number(rawLength,2);
    while(sLength.size()<4)
        sLength = "0" + sLength;
    item->addChild(new QTreeWidgetItem(QStringList() <<
                                       sLength + " .... = Header Length:" + headerLength));

    QString PSH = package_data[row_number].GetTcpPSH();
    QString URG = package_data[row_number].GetTcpURG();
    QString ACK = package_data[row_number].GetTcpACK();
    QString RST = package_data[row_number].GetTcpRST();
    QString SYN = package_data[row_number].GetTcpSYN();
    QString FIN = package_data[row_number].GetTcpFIN();
    QString FLAG = "";

    if(PSH == "1")
        FLAG += "PSH,";
    if(URG == "1")
        FLAG += "UGR,";
    if(ACK == "1")
        FLAG += "ACK,";
    if(RST == "1")
        FLAG += "RST,";
    if(SYN == "1")
        FLAG += "SYN,";
    if(FIN == "1")
        FLAG += "FIN,";
    FLAG = FLAG.left(FLAG.length()-1);

    if(SYN == "1"){
        item->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 0 (relative ack number)"));
    }
    if(SYN == "1" && ACK == "1"){
        item->addChild(new QTreeWidgetItem(QStringList()<<"Sequence Number: 0 (relative sequence number)"));
        item->addChild(new QTreeWidgetItem(QStringList()<<"Acknowledgment Number: 1 (relative ack number)"));
    }
    QTreeWidgetItem* flagTree = new QTreeWidgetItem(QStringList()<<"Flags:" + flag + " (" + FLAG + ")");
    item->addChild(flagTree);
    QString temp = URG == "1"?"Set":"Not set";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .." + URG + ". .... = Urgent(URG):" + temp));
    temp = ACK == "1"?"Set":"Not set";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... ..." + ACK + " .... = Acknowledgment(ACK):" + temp));
    temp = PSH == "1"?"Set":"Not set";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... " + PSH + "... = Push(PSH):" + temp));
    temp = RST == "1"?"Set":"Not set";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ." + RST + ".. = Reset(RST):" + temp));
    temp = SYN == "1"?"Set":"Not set";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... .." + SYN + ". = Syn(SYN):" + temp));
    temp = FIN == "1"?"Set":"Not set";
    flagTree->addChild(new QTreeWidgetItem(QStringList()<<".... .... ..." + FIN + " = Fin(FIN):" + temp));

    QString window = package_data[row_number].GetTcpWinSize();
    QString checksum = "0x" + package_data[row_number].GetTcpCheckSum();
    QString urgent = package_data[row_number].GetTcpUrgentP();
    item->addChild(new QTreeWidgetItem(QStringList()<<"window:" + window));
    item->addChild(new QTreeWidgetItem(QStringList()<<"checksum:" + checksum));
    item->addChild(new QTreeWidgetItem(QStringList()<<"Urgent Pointer:" + urgent));

}

void MainWindow::ShowUdp(){
    QString srcPort = package_data[row_number].GetUdpSrcPort();
    QString desPort = package_data[row_number].GetUdpDesPort();
    QString Length = package_data[row_number].GetUdpDataLen();
    QString checksum = "0x" + package_data[row_number].GetUdpCheckSum();
    QTreeWidgetItem*item5 = new QTreeWidgetItem(QStringList()<<"User Datagram Protocol, Src Port:" + srcPort + ", Dst Port:" + desPort);
    ui->treeWidget->addTopLevelItem(item5);
    item5->addChild(new QTreeWidgetItem(QStringList()<<"Source Port:" + srcPort));
    item5->addChild(new QTreeWidgetItem(QStringList()<<"Destination Port:" + desPort));
    item5->addChild(new QTreeWidgetItem(QStringList()<<"length:" + Length));
    item5->addChild(new QTreeWidgetItem(QStringList()<<"Checksum:" + checksum));
    int udpLength = Length.toUtf8().toInt();
    if(udpLength > 0){
        item5->addChild(new QTreeWidgetItem(QStringList()<<"UDP PayLoad (" + QString::number(udpLength - 8) + " bytes)"));
    }
}

void MainWindow::on_tableWidget_currentCellChanged(int currentRow,int previousRow)
{
    if(currentRow != previousRow && currentRow >= 0)
        on_tableWidget_cellClicked(currentRow);
    else
        return;
}

void MainWindow::on_lineEdit_4_returnPressed()
{
    on_pushButton_3_clicked();
}

void MainWindow::on_lineEdit_4_textChanged()
{
    QRegExp reg_exp("((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])");
    ui->lineEdit_4->setValidator(new QRegExpValidator(reg_exp,this));
}
