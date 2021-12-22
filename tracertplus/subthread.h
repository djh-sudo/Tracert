#ifndef SUBTHREAD_H
#define SUBTHREAD_H
#include <QThread>
#include <QString>
#include <QAtomicInt>
#include "pcap.h"
#include "winsock2.h"
#include "datapackage.h"
/**
  * SubThread class is used to analysis packge,
  * when analysing is over,sub-thread will send result
  * to main thread.
*/

class SubThread:public QThread
{
    Q_OBJECT
private:
    pcap_t *pointer;            // data package pointer
    struct pcap_pkthdr*header;  // package header pointer
    const u_char *pkt_data;     // pckage content pointer
    time_t local_time_version_sec;
    struct tm local_time;
    char time_string[16];
    QAtomicInteger<bool> is_done;// done flag
    int ip_payload;

protected:
    static QString ByteToHex(u_char *str, int size);
    void run() override;

signals:
    void send(DataPackage data_package);

public:
    SubThread();
    bool SetPointer(pcap_t *pointer);
    void SetFlag();
    void ResetFlag();

    int EthernetHandle(const u_char *pkt_content,QString& info);
    int IpHandle(const u_char *pkt_content);
    int IcmpHandle(const u_char *pkt_content,QString&info);
    int ArpHandle(const u_char *pkt_content,QString&info);
    int TcpHandle(const u_char *pkt_content,QString&info);
    int UdpHandle(const u_char *pkt_content,QString&info);
};

#endif // SUBTHREAD_H
