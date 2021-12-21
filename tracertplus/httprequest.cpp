#include "httprequest.h"
#include <QTextCodec>
#include <QDebug>

HttpRequest::HttpRequest()
{
    this->sock = INVALID_SOCKET;
    this->request = QUERY_IP;
    this->position = "";
    this->ip_addr = nullptr;
    this->buffer_size = 1024;
}

bool HttpRequest::GetIp(QString name){
    // load the winsock
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2,2),&wsa) != 0){
        return false;
    }
    ZeroMemory(result,30);
    this->ip_addr = (char*)name.toStdString().c_str();
    if(inet_addr(ip_addr) == INADDR_NONE){
        hostent* host = gethostbyname(ip_addr);
        if(host){
            ip_addr = inet_ntoa(*(in_addr*)host->h_addr);
        }else{
            ip_addr = nullptr;
            return false;
        }
    }
    memcpy(result,ip_addr,strlen(ip_addr));
    return true;
}

bool HttpRequest::ConnectHttpServer(){
    sock = socket(AF_INET,SOCK_STREAM,0);
    if(sock == INVALID_SOCKET){
        return false;
    }else{
        SOCKADDR_IN info;
        info.sin_port = htons(80);
        info.sin_family = AF_INET;
        info.sin_addr.s_addr = inet_addr(result);
        if(::connect(sock,(SOCKADDR*)&info,sizeof(SOCKADDR)) != 0){
            return false;
        }
    }
    return true;
}

bool HttpRequest::SetSocketInfo(){
    if(setsockopt(sock,SOL_SOCKET,SO_RCVBUF,(char*)&buffer_size,sizeof(int)) == SOCKET_ERROR){
        return false;
    }
    if(setsockopt(sock,SOL_SOCKET,SO_SNDBUF,(char*)&buffer_size,sizeof(int)) == SOCKET_ERROR){
        return false;
    }
    return true;
}

bool HttpRequest::GetPosition(){
    char package[400] = "GET /ipquery"
                        "?ip=";
    strcat(package,request.toStdString().c_str());
    strcat(package," HTTP/1.1\r\nHost: "
                   "ip.ws.126.net\r\n"
                   "Connection: keep-alive\r\n"
                   "Cache-Control: max-age=0\r\n"
                   "Upgrade-Insecure-Requests: 1\r\n"
                   "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n"
                   "Accept-Language: zh-CN,zh;q=0.8\r\n\r\n");
    char recv_buffer[MAX_RECV_LENGTH];
    ZeroMemory(recv_buffer,MAX_RECV_LENGTH);
    // get server ip
    if(!GetIp("ip.ws.126.net")) return false;
    if(!ConnectHttpServer()) return false;
    if(!SetSocketInfo() && sock) return false;
    if(::send(sock,package,strlen(package),0) <= 0) return false;
    if(::recv(sock,recv_buffer,sizeof(recv_buffer),0) <= 0)return false;
    QTextCodec *codec = QTextCodec::codecForName("GBK");
    position = codec->toUnicode(recv_buffer);
    return true;
}


QString HttpRequest::GetResult(){
    return result;
}

void HttpRequest::SetIpAddr(QString ip_addr){
    this->request = ip_addr;
}

void HttpRequest::run(){
    for(int i = 0; i < 5; i++){
        position = "";
        if(GetPosition()){
            int index_start = position.indexOf('{');
            int index_end = position.indexOf('}');
            if(index_start != 0 && index_end != 0){
                QString sub_str = position.mid(index_start + 1,index_end - index_start - 1);
                sub_str.replace("\"","");
                sub_str.replace("city","");
                sub_str.replace("province","");
                sub_str.replace(":","");
                emit query(sub_str);
                return;
            }
            else
                sleep(1);
        }
        else
            sleep(1);
    }
    emit query("fail to resolve!");
    return;
}
