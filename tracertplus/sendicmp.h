#ifndef SENDICMP_H
#define SENDICMP_H
/**
 * This is tracert header file
 * using icmp package to detect
 * @author:djh-sudo
 * # detail:https://github.com/djh-sudo
 * # if you have any question,pls contact me
 * at djh113@126.com
*/
#include <QThread>
#include "format.h"
#include "winsock2.h"
#include "ws2tcpip.h"
#include "format.h"


/*
 * define some const variable
 * these var is default to set
*/

const int ICMP_REQUEST = 8;
const int ICMP_REPLY = 0;
const int ICMP_TTLE = 11;

const int ICMP_MAX_HOP = 30;
const int ICMP_MAX_TIMEOUT = 3000;
const QString TRACE_EXAMPLE = "baidu.com";
const int ICMP_DATA_SIZE = 32;
const int ICMP_MAX_LENGTH = 512;
const char PADDING_LETTER = 'E';


class SendIcmp:public QThread
{
    Q_OBJECT
private:
    int max_hop;      // max hop(default is 30)
    int timeout;      // timeout(ms,default is 3000 ms)
    QString ip_name;  // ip addr or domain
    SOCKET raw_sock;  // raw sock
    ICMP_HEADER* icmp;// icmp header
    sockaddr_in des_sock_addr;  // des addr
    sockaddr_in recv_sock_addr; // recv addr
    u_long des_ip;              // des ip addr
    char padding_letter;        // icmp padding addr
    bool reach_des;             // [flag] reach the des
    volatile bool is_kill;      // [flag] thread been killed
    int ttl;                    // icmp time to live
    u_short sequence;           // sequence
    u_long round_trip_time;     // time stamp
    // send and recv buffer
    char sender_buffer[sizeof(ICMP_HEADER) + ICMP_DATA_SIZE];
    char recv_buffer[ICMP_MAX_LENGTH];
protected:
    // override virtual function
    void run() override;
signals:
    // signal to notice GUI thread
    void send(QString info);
public:
    SendIcmp();
    // generate checksum of icmp package
    u_short GenerateCheckSum(u_short*p_buffer,int size);
    // initialize the env
    bool Init();
    // assmble the icmp package data
    bool AssembleData();
    // send data to destination
    bool SendData(u_short seq_no);
    // recv data from des
    bool RecvData();
    // check recv data is correct icmp
    bool CheckRecvData(char* recv_buffer,int size);
    // set the parameter
    void SetIpName(QString ip_name);  // ip/name
    void SetMaxhop(int max_hop);      // max hop
    void SetTimeout(int timeout);     // time out
    void SetKillSig();                // kill thread
    void SetPadding(QString padding); // padding
};

#endif // SENDICMP_H
