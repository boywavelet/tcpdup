# tcpdup

## install

### Requirements
* gcc 
* cmake
* libpcap

### Steps
* cmake . && make
* bin/testall: check all the cases
* bin/tcpdup: capture the desired tcp flow
* bin/transfer: retransfer the tcp flow to the desired destination

### Useage

#### tcpdup

`tcpdup -i <net> -t <ip> -q <port> -s <ip> -p <port>  

    -i <net>   netword interface name  
    -t <ip>    monitored server ip
    -q <port>  monitored server port
    -s <ip>    transfer server ip
    -p <port>  transfer server port
    -h         Show This`

#### transfer

`transfer -t <ip> -q <port> -s <ip> -p <port>  

    -t <ip>    monitored server ip
    -q <port>  monitored server port
    -s <ip>    transfer server ip
    -p <port>  transfer server port
    -l <port>  [OPTIONAL:23456] listen port
    -e <time>  [OPTIONAL:1000] epoll wait time
    -m <mode>  [OPTIONAL:3] close mode
    -d <flag>  [OPTIONAL:0] debug
    -h         Show This`
