#include "datapackage.h"
#include <QMetaType>
#include <QVector>
#include "winsock.h"

DataPackage::DataPackage()
{
    qRegisterMetaType<DataPackage>("DataPackage");
    this->time_stamp = "";
    this->data_length = 0;
    this->pkt_content = nullptr;
    this->type = 0;
}

void DataPackage::SetDataLength(unsigned int length){
    this->data_length = length;
}

void DataPackage::SetTimeStamp(QString time_stamp){
    this->time_stamp = time_stamp;
}

void DataPackage::SetPackageType(int type){
    this->type = type;
}

void DataPackage::SetPackagePointer(const u_char *pkt_content, int size){
    this->pkt_content = (u_char*)malloc(size);
    memcpy((char*)(this->pkt_content), pkt_content,size);
}

void DataPackage::SetPackageInfo(QString info){
    this->info = info;
}

QString DataPackage::ByteToHex(const u_char *str, int size){
    QString res = "";
    for(int i = 0;i < size;i++){
        char one = str[i] >> 4;
        if(one >= 0x0A)
            one = one + 0x41 - 0x0A;
        else one = one + 0x30;
        char two = str[i] & 0xF;
        if(two >= 0x0A)
            two = two  + 0x41 - 0x0A;
        else two = two + 0x30;
        res.append(one);
        res.append(two);
    }
    return res;
}

QString DataPackage::GetTimeStamp(){
    return this->time_stamp;
}

QString DataPackage::GetDataLength(){
    return QString::number(this->data_length);
}

QString DataPackage::GetInfo(){
    return info;
}

QString DataPackage::GetType(){
    switch (type) {
    case 20:return "TCP";
    case 21:return "UDP";
    case 22:return "ARP";
    default:return "ICMP";
    }
}

QString DataPackage::GetSource(){
    if(type == 22)
        return GetArpSrcEtherAddr();
    else
        return GetSrcIpAddr();
}

QString DataPackage::GetDestination(){
    if(type == 22)
        return GetArpDesEtherAddr();
    else
        return GetDesIpAddr();
}
/***********-**********-ethenet part-**********-***********/

QString DataPackage::GetDesMacAddr(){
    ETHER_HEADER*ethernet;
    ethernet = (ETHER_HEADER*)pkt_content;
    if(ethernet){
        u_char*addr = ethernet->ether_des_host;
        if(addr){
            QString res = ByteToHex(addr,1) + ":"
                    + ByteToHex((addr+1),1) + ":"
                    + ByteToHex((addr+2),1) + ":"
                    + ByteToHex((addr+3),1) + ":"
                    + ByteToHex((addr+4),1) + ":"
                    + ByteToHex((addr+5),1);
            if(res == "FF:FF:FF:FF:FF:FF")
                return "FF:FF:FF:FF:FF:FF(Broadcast)";
            else
                return res;
        }
    }
    return "";
}

QString DataPackage::GetSrcMacAddr(){
    ETHER_HEADER*ethernet;
    ethernet = (ETHER_HEADER*)pkt_content;
    if(ethernet){
        u_char*addr = ethernet->ether_src_host;
        if(addr){
            QString res = ByteToHex(addr,1) + ":"
                    + ByteToHex((addr+1),1) + ":"
                    + ByteToHex((addr+2),1) + ":"
                    + ByteToHex((addr+3),1) + ":"
                    + ByteToHex((addr+4),1) + ":"
                    + ByteToHex((addr+5),1);
            if(res == "FF:FF:FF:FF:FF:FF")
                return "FF:FF:FF:FF:FF:FF(Broadcast)";
            else
                return res;
        }
    }
    return "";
}

QString DataPackage::GetMacType(){
    ETHER_HEADER*ethernet;
    ethernet = (ETHER_HEADER*)pkt_content;
    u_short ethernet_type = ntohs(ethernet->ether_type);
    switch (ethernet_type) {
    case 0x0800: return "IPv4(0x800)";
    case 0x0806:return "ARP(0x0806)";
    default:{
        return "";
    }
    }
}
/***********-**********-end of ethernet-**********-***********/

/***********-**********-ip package part-**********-***********/
QString DataPackage::GetDesIpAddr(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in desAddr;
    desAddr.sin_addr.s_addr = ip->des_addr;
    return QString(inet_ntoa(desAddr.sin_addr));
}

QString DataPackage::GetSrcIpAddr(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    sockaddr_in srcAddr;
    srcAddr.sin_addr.s_addr = ip->src_addr;
    return QString(inet_ntoa(srcAddr.sin_addr));
}

QString DataPackage::GetIpTTL(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ip->ttl);
}

QString DataPackage::GetIpProtocol(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int protocol = ip->protocol;
    switch (protocol) {
    case 1:return "ICMP (1)";
    case 6:return "TCP (6)";
    case 17:return "UDP (17)";
    default:{
        return "";
    }
    }
}

QString DataPackage::GetIpVersion(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ip->versiosn_head_length >> 4);
}

QString DataPackage::GetIpHeaderLength(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    QString res = "";
    int length = ip->versiosn_head_length & 0x0F;
    if(length == 5) res = "20 bytes (5)";
    else res = QString::number(length * 4)
            + "bytes ("
            + QString::number(length) + ")";
    return res;
}

QString DataPackage::GetIpTos(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->TOS));
}

QString DataPackage::GetIpTotalLength(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->total_length));
}

QString DataPackage::GetIpIdentification(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->identification),16);
}

QString DataPackage::GetIpFlag(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset)& 0xe000) >> 8,16);
}

QString DataPackage::GetIpReservedBit(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    int bit = (ntohs(ip->flag_offset) & 0x8000) >> 15;
    return QString::number(bit);
}

QString DataPackage::GetIpDF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset) & 0x4000) >> 14);
}

QString DataPackage::GetIpMF(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number((ntohs(ip->flag_offset) & 0x2000) >> 13);
}

QString DataPackage::GetIpFragmentOffset(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->flag_offset) & 0x1FFF);
}

QString DataPackage::GetIpCheckSum(){
    IP_HEADER*ip;
    ip = (IP_HEADER*)(pkt_content + 14);
    return QString::number(ntohs(ip->checksum),16);
}

/***********-**********-end of ip part -**********-***********/

/***********-**********-icmp package part-**********-***********/
QString DataPackage::GetIcmpType(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number((icmp->type));
}

QString DataPackage::GetIcmpCode(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number((icmp->code));
}

QString DataPackage::GetIcmpCheckSum(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->checksum),16);
}

QString DataPackage::GetIcmpSequeue(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->sequence));
}

QString DataPackage::GetIcmpData(int size){
    char*icmp;
    icmp = (char*)(pkt_content + 14 + 20 + 8);
    QString res= "";
    for(int i = 0;i < size;i++){
        res += (*icmp);
        icmp++;
    }
    return res;
}

int DataPackage::GetPackageType(){
    return this->type;
}

QString DataPackage::GetIcmpIdentification(){
    ICMP_HEADER*icmp;
    icmp = (ICMP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(icmp->identification));
}

/***********-**********-end of icmp-**********-***********/

/***********-**********-arp package-**********-***********/
QString DataPackage::GetArpHardwareType(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int type = ntohs(arp->hardware_type);
    QString res = "";
    if(type == 0x0001) res = "Ethernet(1)";
    else res = QString::number(type);
    return res;
}

QString DataPackage::GetArpProtocolType(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int type = ntohs(arp->protocol_type);
    QString res = "";
    if(type == 0x0800) res = "IPv4(0x0800)";
    else res = QString::number(type);
    return res;
}

QString DataPackage::GetArpHardwareLen(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    return QString::number(arp->mac_length);
}

QString DataPackage::GetArpProtocolLen(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    return QString::number(arp->ip_length);
}

QString DataPackage::GetArpOpCode(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    int code = ntohs(arp->op_code);
    QString res = "";
    if(code == 1) res  = "request(1)";
    else if(code == 2) res = "reply(2)";
    return res;
}

QString DataPackage::GetArpSrcEtherAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        u_char* addr = arp->src_eth_addr;
        if(addr){
            QString res = ByteToHex(addr,1) + ":"
                    + ByteToHex((addr+1),1) + ":"
                    + ByteToHex((addr+2),1) + ":"
                    + ByteToHex((addr+3),1) + ":"
                    + ByteToHex((addr+4),1) + ":"
                    + ByteToHex((addr+5),1);
            return res;
        }
    }
    return "";
}

QString DataPackage::GetArpSrcIpAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        u_char*addr = arp->src_ip_addr;
        QString srcIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));
        return srcIp;
    }
    return "";
}

QString DataPackage::GetArpDesEtherAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        u_char*addr = arp->des_eth_addr;
        if(addr){
            QString res = ByteToHex(addr,1) + ":"
                    + ByteToHex((addr+1),1) + ":"
                    + ByteToHex((addr+2),1) + ":"
                    + ByteToHex((addr+3),1) + ":"
                    + ByteToHex((addr+4),1) + ":"
                    + ByteToHex((addr+5),1);
            return res;
        }
    }
    return "";
}

QString DataPackage::GetArpDesIpAddr(){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    if(arp){
        u_char*addr = arp->des_ip_addr;
        QString desIp = QString::number(*addr) + "."
                + QString::number(*(addr+1)) + "."
                + QString::number(*(addr+2)) + "."
                + QString::number(*(addr+3));
        return desIp;
    }
    return "";
}

/***********-**********-end of arp-**********-***********/

/***********-**********-tcp package-**********-***********/
QString DataPackage::GetTcpSrcPort(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int port = ntohs(tcp->src_port);
    if(port == 443) return "https(443)";
    return QString::number(port);
}

QString DataPackage::GetTcpDesPort(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int port = ntohs(tcp->des_port);
    if(port == 443) return "https(443)";
    return QString::number(port);
}

QString DataPackage::GetTcpSequence(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohl(tcp->sequence));
}

QString DataPackage::GetTcpAck(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohl(tcp->ack));
}

QString DataPackage::GetTcpHeaderLen(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    int length = (tcp->header_length >> 4);
    if(length == 5) return "20 bytes (5)";
    else return QString::number(length*4) + " bytes (" + QString::number(length) + ")";
}

QString DataPackage::GetTcpRawHeaderLen(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(tcp->header_length >> 4);
}

QString DataPackage::GetTcpFlags(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(tcp->flags,16);
}

QString DataPackage::GetTcpPSH(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x08) >> 3);
}

QString DataPackage::GetTcpACK(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x10) >> 4);
}

QString DataPackage::GetTcpSYN(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x02) >> 1);
}

QString DataPackage::GetTcpURG(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x20) >> 5);
}

QString DataPackage::GetTcpFIN(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number((tcp->flags) & 0x01);
}

QString DataPackage::GetTcpRST(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(((tcp->flags) & 0x04) >> 2);
}

QString DataPackage::GetTcpWinSize(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->window_size));
}

QString DataPackage::GetTcpCheckSum(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->checksum),16);
}

QString DataPackage::GetTcpUrgentP(){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    return QString::number(ntohs(tcp->urgent));
}

QString DataPackage::GetTcpOpKind(int kind){
    switch(kind){
    case 0:return "EOL";              // end of list
    case 1:return "NOP";              // no operation
    case 2:return "MSS";              // max segment
    case 3:return "WSOPT";            // window scaling factor
    case 4:return "SACK-Premitted";   // support SACK
    case 5:return "SACK";             // SACK Block
    case 8:return "TSPOT";            // Timestamps
    case 19:return "TCP-MD5";         // MD5
    case 28:return "UTP";             // User Timeout
    case 29:return "TCP-AO";          // authenticated
    }
}

int DataPackage::getTcpOpRawKind(int offset){
    u_char*tcp;
    tcp = (u_char*)(pkt_content + 14 + 20 + offset + 20);
    return *tcp;
}
/***********-**********-end of arp-**********-***********/

/***********-**********-udp package-**********-***********/
QString DataPackage::GetUdpSrcPort(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    int port = ntohs(udp->src_port);
    if(port == 53) return "domain(53)";
    else return QString::number(port);
}

QString DataPackage::GetUdpDesPort(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    int port = ntohs(udp->des_port);
    if(port == 53) return "domain(53)";
    else return QString::number(port);
}

QString DataPackage::GetUdpDataLen(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    return QString::number(ntohs(udp->data_length));
}

QString DataPackage::GetUdpCheckSum(){
    UDP_HEADER*udp;
    udp = (UDP_HEADER*)(pkt_content + 20 + 14);
    return QString::number(ntohs(udp->checksum),16);
}
/***********-**********-end of udp-**********-***********/
