#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H
#include <QString>
#include "format.h"

class DataPackage
{
private:
    u_int data_length;   // data package length
    QString time_stamp;  // time stamp
    QString info;        // a brief introduction
    int type;            // package type

protected:
    static QString ByteToHex(const u_char*str,int size);

public:
    // root pointer of package data
    const u_char* pkt_content;
    DataPackage();
    // set the var
    void SetDataLength(unsigned int length);     // set the package length
    void SetTimeStamp(QString time_stamp);       // set timestamp
    void SetPackageType(int type);               // set package type
    void SetPackagePointer(
            const u_char *pkt_content,u_int size); // set package pointer
    void SetPackageInfo(QString info);           // set package information

    // get the var
    QString GetDataLength();         // package length
    QString GetTimeStamp();          // timestamp
    int GetPackageType();            // package type [int]
    QString GetType();               // package type [QString]
    QString GetInfo();               // a breif package information
    QString GetSource();             // source address of package
    QString GetDestination();        // destination address of package

    // Ethernet
    QString GetDesMacAddr();         // destination MAC address
    QString GetSrcMacAddr();         // source MAC address
    QString GetMacType();            // type of MAC address

    // IP
    QString GetDesIpAddr();          // destination ip address
    QString GetSrcIpAddr();          // source ip address
    QString GetIpProtocol();         // ip protocol
    QString GetIpVersion();          // ip version
    QString GetIpHeaderLength();     // ip head length
    QString GetIpTos();              // ip tos
    QString GetIpTotalLength();      // ip total package length
    QString GetIpIdentification();   // ip identification
    QString GetIpFlag();             // ip flag
    QString GetIpReservedBit();      // the reserved bit
    QString GetIpDF();               // Don't fragment
    QString GetIpMF();               // More fragment
    QString GetIpFragmentOffset();   // the offset of package
    QString GetIpTTL();              // ip ttl [time to live]
    QString GetIpCheckSum();         // the checksum

    // ICMP
    QString GetIcmpType();           // icmp type
    QString GetIcmpCode();           // icmp code
    QString GetIcmpCheckSum();       // icmp checksum
    QString GetIcmpIdentification(); // icmp identification
    QString GetIcmpSequeue();        // icmp sequence
    QString GetIcmpData(int size);   // icmp data

    // ARP
    QString GetArpHardwareType();   // arp hardware type
    QString GetArpProtocolType();   // arp protocol type
    QString GetArpHardwareLen();    // arp hardware length
    QString GetArpProtocolLen();    // arp protocol length
    QString GetArpOpCode();         // arp operation code
    QString GetArpSrcEtherAddr();   // arp source ethernet address
    QString GetArpSrcIpAddr();      // arp souce ip address
    QString GetArpDesEtherAddr();   // arp destination ethernet address
    QString GetArpDesIpAddr();      // arp destination ip address

    // TCP
    QString GetTcpSrcPort();          // tcp source port
    QString GetTcpDesPort();          // tcp destination port
    QString GetTcpSequence();         // tcp sequence
    QString GetTcpAck();              // acknowlegment
    QString GetTcpHeaderLen();        // tcp head length
    QString GetTcpRawHeaderLen();     // tcp raw head length [default is 0x05]
    QString GetTcpFlags();            // tcp flags
    QString GetTcpPSH();              // PSH flag
    QString GetTcpACK();              // ACK flag
    QString GetTcpSYN();              // SYN flag
    QString GetTcpURG();              // URG flag
    QString GetTcpFIN();              // FIN flag
    QString GetTcpRST();              // RST flag
    QString GetTcpWinSize();          // tcp window size
    QString GetTcpCheckSum();         // tcp checksum
    QString GetTcpUrgentP();          // tcp urgent pointer
    QString GetTcpOpKind(int kind);   // tcp option kind
    int getTcpOpRawKind(int offset);  // tcp raw option kind

    // UDP
    QString GetUdpSrcPort();          // get udp source port
    QString GetUdpDesPort();          // get udp destination port
    QString GetUdpDataLen();          // get udp data length
    QString GetUdpCheckSum();         // get udp checksum
};

#endif // DATAPACKAGE_H
