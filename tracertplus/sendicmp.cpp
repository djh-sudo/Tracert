#include "sendicmp.h"


SendIcmp::SendIcmp(){
    this->timeout = ICMP_MAX_TIMEOUT;
    this->max_hop = ICMP_MAX_HOP;
    this->ip_name = TRACE_EXAMPLE;
    this->padding_letter = PADDING_LETTER;
    this->raw_sock = INVALID_SOCKET;
    this->ttl = 1;
    this->sequence = 0;
    this->round_trip_time = 0;
    this->is_kill = false;
    this->reach_des = false;
    memset(sender_buffer,0,sizeof(ICMP_HEADER) + ICMP_DATA_SIZE);
    memset(recv_buffer,0,ICMP_MAX_LENGTH);
}

void SendIcmp::run(){
    // init the env
    if(!Init()) return;
    // assemble data
    if(!AssembleData()) return;
    // starting tracert
    u_short seq_no = 0;

    while(!reach_des && max_hop && !is_kill){
        max_hop--;
        // send part
        if(!SendData(seq_no)) return;
        seq_no++;
        // recv part
        if(!RecvData()) return;
        ttl++;
    }
    if(!is_kill)
        emit send("Trace is completed!\n");
    else
        emit send("Trace is killed!\n");
    closesocket(raw_sock);
    WSACleanup();
    return;
}

u_short SendIcmp::GenerateCheckSum(u_short *p_buffer, int size){
    // 1.checksum = 0
    u_long checksum = 0;
    // 2.Add every two bytes
    while(size > 1){
        checksum += *p_buffer++;
        size -=  sizeof(u_short);
    }
    // 3.if there is one byte left, then continue to add
    if(size > 0) checksum += *(u_char*)p_buffer;
    // 4.Add the high 16 bits and the low 16 bits
    while(checksum >> 16){
        checksum = (checksum >> 16) + (checksum & 0xFFFF);
    }
    // 5.Binary negation
    return (u_short)((~checksum) & 0xFFFF);
}

void SendIcmp::SetIpName(QString ip_name){
    this->ip_name = ip_name;
}

void SendIcmp::SetMaxhop(int max_hop){
    this->max_hop = max_hop;
}

void SendIcmp::SetTimeout(int timeout){
    this->timeout = timeout;
}

void SendIcmp::SetKillSig(){
    this->is_kill = true;
}

void SendIcmp::SetPadding(QString padding){
    if(padding.length() > 1)
        return;
    else{
        this->padding_letter = (padding.toStdString())[0];
        return;
    }
}

bool SendIcmp::Init(){
    // initialize
    this->is_kill = false;
    this->reach_des = false;
    this->ttl = 1;
    // load the Winsock
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2,2),&wsa) != 0){
        // to notice GUI thread
        emit send("Fail to initialize the winsock2 dll!\n"
                  "error code: " + QString::number(WSAGetLastError()));
        return false;
    }
    this->raw_sock = WSASocket(AF_INET,
                               SOCK_RAW,
                               IPPROTO_ICMP,
                               NULL,
                               0,
                               WSA_FLAG_OVERLAPPED);

    const char* ip_addr = ip_name.toStdString().c_str();
    des_ip = inet_addr(ip_addr);
    if(des_ip == INADDR_NONE){
        // fail to convert
        hostent* host = gethostbyname(ip_addr);
        if(host){
            des_ip = (*(in_addr*)host->h_addr).s_addr;
            emit send("Tracing route to [domain] "
                      + QString(inet_ntoa(*(in_addr*)(&des_ip)))
                      + "\nwith maxmum of " + QString::number(max_hop)
                      + " hops\nwith maxmum timeout " + QString::number(timeout)
                      + " (ms)\n");
        }else{
            emit send("Can't resolve the host name/ip addr!"
                      "\nplease check the input ["
                      + ip_name + "]\n"
                      "or check the computer can surf Internet?");
            WSACleanup();
            return false;
        }
    }else{
        emit send("Tracing route to [ip addr]"
                  + QString(inet_ntoa(*(in_addr*)(&des_ip)))
                  + "\nwith maxmum of " + QString::number(max_hop)
                  + " hops\nwith maxmum timeout " + QString::number(timeout)
                  + " (ms)\n");
    }

    // padding the zero
    ZeroMemory(&des_sock_addr,sizeof(sockaddr_in));
    des_sock_addr.sin_family = AF_INET;
    des_sock_addr.sin_addr.s_addr = des_ip;
    if(raw_sock == INVALID_SOCKET){
        emit send("Fail to create a raw socket!\n"
                  "error code: " + QString::number(WSAGetLastError()) + "\n");
        WSACleanup();
        return false;
    }
    return true;
}

bool SendIcmp::AssembleData(){
    // setting the port arttibute
    if(setsockopt(raw_sock,SOL_SOCKET,SO_RCVTIMEO,(char*)& timeout,sizeof(timeout)) == SOCKET_ERROR){
        emit send("Fail to set recv timeout!\n"
                  "error code: " + QString::number(WSAGetLastError()));
        closesocket(raw_sock);
        WSACleanup();
        return false;
    }
    // create icmp pakcage buffer
    memset(sender_buffer,0,sizeof(sender_buffer));
    memset(recv_buffer,0,sizeof(recv_buffer));

    // filling the icmp
    icmp = (ICMP_HEADER*)sender_buffer;
    icmp->type = ICMP_REQUEST;
    icmp->code = 0;
    icmp->identification = htons((u_short)GetCurrentProcessId());

    // padding the data
    memset(sender_buffer + sizeof(ICMP_HEADER),padding_letter,ICMP_DATA_SIZE);
    return true;
}

bool SendIcmp::SendData(u_short seq_no){
    // setting the ttl
    setsockopt(raw_sock,IPPROTO_IP,IP_TTL,(char*)& ttl,sizeof(ttl));
    // padding the icmp
    ((ICMP_HEADER*)sender_buffer)->sequence = htons(seq_no);
    ((ICMP_HEADER*)sender_buffer)->checksum = 0;
    ((ICMP_HEADER*)sender_buffer)->checksum = GenerateCheckSum((u_short*)sender_buffer,sizeof(ICMP_HEADER) + ICMP_DATA_SIZE);
    // record seq and time
    sequence = htons(((ICMP_HEADER*)sender_buffer)->sequence);
    round_trip_time =  GetTickCount();
    // send
    if(sendto(raw_sock,
              sender_buffer,
              sizeof(sender_buffer),
              0,
              (sockaddr*)&des_sock_addr,
              sizeof(des_sock_addr)) == SOCKET_ERROR){
        if(WSAGetLastError() == WSAEHOSTUNREACH){
            emit send("Destination host unreachable\n"
                      "Trace complete!\n");
        }
        closesocket(raw_sock);
        WSACleanup();
        return false;
    }
    return true;
}

bool SendIcmp::RecvData(){
    sockaddr_in from;
    int len = sizeof(from);
    int read_data_len = 0;
    while(!is_kill){
        read_data_len = recvfrom(raw_sock,
                                 recv_buffer,
                                 ICMP_MAX_LENGTH,
                                 0,
                                 (sockaddr*)& from,
                                 &len);
        if(read_data_len != SOCKET_ERROR){
            if(CheckRecvData(recv_buffer,read_data_len)){
                if(recv_sock_addr.sin_addr.s_addr == des_sock_addr.sin_addr.s_addr){
                    reach_des = true;
                    emit send(QString::number(ttl)
                              + " Reach destination "
                              + QString(inet_ntoa(des_sock_addr.sin_addr))
                              + "\n");
                }
                break;
            }
        }else if(WSAGetLastError() == WSAETIMEDOUT){
            // time out
            emit send(QString::number(ttl) + " * Request timed out!");
            break;
        }else{
            emit send("Fail to call recvfrom\n"
                      "error code: " + QString::number(WSAGetLastError()));
            WSACleanup();
            return false;
        }
    }
    return true;
}

bool SendIcmp::CheckRecvData(char *recv_buffer, int size){
    IP_HEADER* ip = (IP_HEADER*)(recv_buffer);
    int ip_len = (ip->versiosn_head_length & 0x0F) * 4;
    if(size < int(ip_len + sizeof(ICMP_HEADER))) return false;
    icmp = (ICMP_HEADER*)(recv_buffer + ip_len);
    u_short id,seq;
    if(icmp->type == ICMP_REPLY){
        id = ntohs(icmp->identification);
        seq = ntohs(icmp->sequence);
    }
    else if(icmp->type == ICMP_TTLE){
        char* ip = recv_buffer + ip_len + sizeof(ICMP_HEADER);
        int len = (((IP_HEADER*)ip)->versiosn_head_length & 0x0F) * 4;
        ICMP_HEADER*temp_icmp = (ICMP_HEADER*)(ip + len);
        id = ntohs(temp_icmp->identification);
        seq = ntohs(temp_icmp->sequence);
    }
    else
        return false;
    if(id != (u_short)GetCurrentProcessId() || seq != sequence) return false;
    if(icmp->type ==ICMP_REPLY || icmp->type == ICMP_TTLE){
        recv_sock_addr.sin_addr.s_addr = ip->src_addr;
        round_trip_time = GetTickCount() - round_trip_time;
        if(round_trip_time)
            emit send(QString::number(ttl)
                      + " "
                      + QString(inet_ntoa(recv_sock_addr.sin_addr))
                      + "  "
                      + QString::number(round_trip_time) + " ms");
        else
            emit send(QString::number(ttl)
                      + " "
                      + QString(inet_ntoa(recv_sock_addr.sin_addr))
                      + " <1 ms");
        return true;
    }
    return false;
}

