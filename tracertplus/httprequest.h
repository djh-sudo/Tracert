#ifndef HTTPREQUEST_H
#define HTTPREQUEST_H

#include <QThread>
#include "winsock2.h"

const int MAX_RECV_LENGTH = 1024;
const QString QUERY_IP = "220.181.38.148";


class HttpRequest:public QThread
{
    Q_OBJECT
private:
    QString request;
    SOCKET sock;
    const char*ip_addr;
    char result[30];
    int buffer_size;
    QString position;
protected:
    void run() override;
signals:
    void query(QString);
public:
    HttpRequest();
    bool GetIp(QString name);
    bool ConnectHttpServer();
    bool GetPosition();
    bool SetSocketInfo();

    QString GetResult();
    void SetIpAddr(QString ip_addr);
};

#endif // HTTPREQUEST_H
