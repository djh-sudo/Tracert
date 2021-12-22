#include "subthread.h"
#include <QDebug>

/*
 * tcp - > 20
 * udp -> 21
 * arp -> 22
 * icmp -> type
*/
SubThread::SubThread()
{
    this->is_done = false;
    this->header = nullptr;
    this->pointer = nullptr;
    this->pkt_data = nullptr;
    this->ip_payload = 0;
}

bool SubThread::SetPointer(pcap_t *pointer){
    this->pointer = pointer;
    if(this->pointer) return true;
    else return false;
}

void SubThread::SetFlag(){
    this->is_done = true;
}

void SubThread::ResetFlag(){
    this->is_done = false;
}

QString SubThread::ByteToHex(u_char *str, int size){
    QString res = "";
    for(int i = 0;i < size;i++){
        char one = str[i]>>4;
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

void SubThread::run(){
    unsigned int package_number = 0;
    while(true){
        if(is_done) break;
        int result = pcap_next_ex(pointer,&header,&pkt_data);
        if(result == 0)
            continue;
        local_time_version_sec = header->ts.tv_sec;
        localtime_s(&local_time,&local_time_version_sec);
        strftime(time_string,sizeof(time_string),"%H:%M:%S",&local_time);
        QString info = "";
        int type = EthernetHandle(pkt_data,info);
        if(type != -1){
            DataPackage data;
            u_int len = header->len;
            data.SetPackageType(type);
            data.SetDataLength(len);
            data.SetTimeStamp(QString(time_string));
            data.SetPackagePointer(pkt_data,len);
            data.SetPackageInfo(info);
            emit send(data);
            package_number++;
        }
        else
            continue;
    }
    return;
}

int SubThread::EthernetHandle(const u_char *pkt_content, QString &info){
    ETHER_HEADER* ethernet = (ETHER_HEADER*)pkt_content;
    u_short ethernet_type = ntohs(ethernet->ether_type);
    if(ethernet_type == 0x0800){
        int sub_type = 0;
        ip_payload = 0;
        sub_type = IpHandle(pkt_content);
        if(sub_type == 1){
            return IcmpHandle(pkt_content,info);
        }
        else if(sub_type == 6){
            return TcpHandle(pkt_content,info);
        }
        else if(sub_type == 17){
            return UdpHandle(pkt_content,info);
        }
        else return -1;
    }
    else if(ethernet_type == 0x0806){
        return ArpHandle(pkt_content,info);
    }
    else
        return -1;
}

int SubThread::IpHandle(const u_char *pkt_content){
    IP_HEADER* ip = (IP_HEADER*)(pkt_content + 14);
    ip_payload = (htons(ip->total_length) - (ip->versiosn_head_length & 0x0F) * 4);
    return ip->protocol;
}

// icmp package
/*
 * part of the protocol of type and code
 * if you need detail information, pls check the official documents
+------+------+------------------------------------------------+
| type | code |                   information                  |
+------+------+------------------------------------------------+
|  0   |   0  |     Echo response (ping command response)      |
+------+------+------------------------------------------------+
|      |   0  |             Network unreachable                |
+      +------+------------------------------------------------+
|      |   1  |             Host unreachable                   |
+      +------+------------------------------------------------+
|      |   2  |              Protocol unreachable              |
+      +------+------------------------------------------------+
|   3  |   3  |              Port unreachable                  |
+      +------+------------------------------------------------+
|      |   4  |    Fragmentation is required, but DF is set    |
+      +------+------------------------------------------------+
|      |   5  |        Source route selection failed           |
+      +------+------------------------------------------------+
|      |   6  |            Unknown target network              |
+------+------+------------------------------------------------+
|   4  |   0  | Source station suppression [congestion control]|
+------+------+------------------------------------------------+
|   5  |  any |                  Relocation                    |
+------+------+------------------------------------------------+
|  8   |   0  |       Echo request (ping command request)      |
+------+------+------------------------------------------------+
......

*/
int SubThread::IcmpHandle(const u_char *pkt_content,QString&info){
    ICMP_HEADER* icmp = (ICMP_HEADER*)(pkt_content + 20 + 14);
    u_char type = icmp->type;
    u_char code = icmp->code;
    QString result = "";
    switch (type) {
    case 0:{
        if(!code)
            result = "Echo response (ping)";
        break;
    }
    case 3:{
        switch (code) {
        case 0:{
            result = "Network unreachable";
            break;
        }
        case 1:{
            result = "Host unreachable";
            break;
        }
        case 2:{
            result = "Protocol unreachable";
            break;
        }
        case 3:{
            result = "Port unreachable";
            break;
        }
        case 4:{
            result = "Fragmentation is required, but DF is set";
            break;
        }
        case 5:{
            result = "Source route selection failed";
            break;
        }
        case 6:{
            result = "Unknown target network";
            break;
        }
        default:break;
        }
        break;
    }
    case 4:{
        result = "Source station suppression [congestion control]";
        break;
    }
    case 5:{
        result = "Relocation";
        break;
    }
    case 8:{
        if(!code)
            result = "Echo request (ping)";
        break;
    }
    case 11:{
        if(code == 0){
            result = "TTL equal 0 during transit!";
        }
        break;
    }
    default:break;
    }
    info = result;
    return type;
}

int SubThread::ArpHandle(const u_char *pkt_content, QString &info){
    ARP_HEADER*arp;
    arp = (ARP_HEADER*)(pkt_content + 14);
    u_short op = ntohs(arp->op_code);
    QString res = "";
    u_char*addr = arp->des_ip_addr;

    QString desIp = QString::number(*addr) + "."
            + QString::number(*(addr+1)) + "."
            + QString::number(*(addr+2)) + "."
            + QString::number(*(addr+3));

    addr = arp->src_ip_addr;
    QString srcIp = QString::number(*addr) + "."
            + QString::number(*(addr+1)) + "."
            + QString::number(*(addr+2)) + "."
            + QString::number(*(addr+3));

    u_char* srcEthTemp = arp->src_eth_addr;
    QString srcEth =ByteToHex(srcEthTemp,1) + ":"
            + ByteToHex((srcEthTemp+1),1) + ":"
            + ByteToHex((srcEthTemp+2),1) + ":"
            + ByteToHex((srcEthTemp+3),1) + ":"
            + ByteToHex((srcEthTemp+4),1) + ":"
            + ByteToHex((srcEthTemp+5),1);

    switch (op){
    case 1:{
        info  = "Who has " + desIp + "? Tell " + srcIp;
        break;
    }
    case 2:{
        info = srcIp + " is at " + srcEth;
        break;
    }
    default:break;
    }
    return 22;
}

int SubThread::TcpHandle(const u_char *pkt_content, QString &info){
    TCP_HEADER*tcp;
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    u_short src = ntohs(tcp->src_port);
    u_short des = ntohs(tcp->des_port);
    QString proSend = "";
    QString proRecv = "";
    int type = 3;
    int delta = (tcp->header_length >> 4) * 4;
    int tcpPayLoad = ip_payload - delta;
    if((src == 443 || des == 443) && (tcpPayLoad > 0)){
        if(src == 443)
            proSend = "(https)";
        else proRecv = "(https)";
        u_char *ssl;
        ssl = (u_char*)(pkt_content + 14 + 20 + delta);
        u_char isTls = *(ssl);
        ssl++;
        u_short*pointer = (u_short*)(ssl);
        u_short version = ntohs(*pointer);
        if(isTls >= 20 && isTls <= 23 && version >= 0x0301 && version <= 0x0304){
            type = 6;
            switch(isTls){
            case 20:{
                info = "Change Cipher Spec";
                break;
            }
            case 21:{
                info = "Alert";
                break;
            }
            case 22:{
                info = "Handshake";
                ssl += 4;
                u_char type_temp = (*ssl);
                switch (type_temp) {
                case 1: {
                    info += " Client Hello";
                    break;
                }
                case 2: {
                    info += " Server hello";
                    break;
                }
                case 4: {
                    info += " New Session Ticket";
                    break;
                }
                case 11:{
                    info += " Certificate";
                    break;
                }
                case 16:{
                    info += " Client Key Exchange";
                    break;
                }
                case 12:{
                    info += " Server Key Exchange";
                    break;
                }
                case 14:{
                    info += " Server Hello Done";
                    break;
                }
                default:break;
                }
                break;
            }
            case 23:{
                info = "Application Data";
                break;
            }
            default:{
                break;
            }
            }
            return 20;
        }else type = 7;
    }

    if(type == 7){
        info = "Continuation Data";
    }
    else{
        info += QString::number(src) + proSend+ " -> " + QString::number(des) + proRecv;
        QString flag = "";
        if(tcp->flags & 0x08) flag += "PSH,";
        if(tcp->flags & 0x10) flag += "ACK,";
        if(tcp->flags & 0x02) flag += "SYN,";
        if(tcp->flags & 0x20) flag += "URG,";
        if(tcp->flags & 0x01) flag += "FIN,";
        if(tcp->flags & 0x04) flag += "RST,";
        if(flag != ""){
            flag = flag.left(flag.length()-1);
            info += " [" + flag + "]";
        }
        u_int sequeue = ntohl(tcp->sequence);
        u_int ack = ntohl(tcp->ack);
        u_short window = ntohs(tcp->window_size);
        info += " Seq=" + QString::number(sequeue) + " Ack=" + QString::number(ack) + " win=" + QString::number(window) + " Len=" + QString::number(tcpPayLoad);
    }
    return 20;
}

int SubThread::UdpHandle(const u_char *pkt_content, QString &info){
    UDP_HEADER * udp;
    udp = (UDP_HEADER*)(pkt_content + 14 + 20);
    u_short desPort = ntohs(udp->des_port);
    u_short srcPort = ntohs(udp->src_port);
    if(desPort == 53){ // dns query
        info =  "DNS query";
    }
    else if(srcPort == 53){// dns reply
        info =  "DNS reply";
    }
    else{
        QString res = QString::number(srcPort) + " -> " + QString::number(desPort);
        res += " len = " + QString::number(ntohs(udp->data_length));
        info = res;
    }
    return 21;
}
