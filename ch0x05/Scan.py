# -*- coding: utf-8 -*-
import sys
import logging
from scapy.all import *

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def help():
    print("USAGE")
    print("\t"+sys.argv[0]+" [-c] [-s] [-u] [-x] [-f] [-n] <ip:port>")
    print("OPTIONS")
    print("\t-c:TCP connect scan ")
    print("\t-s:TCP stealth scan")
    print("\t-x:TCP Xmas scan")
    print("\t-f:TCP fin scan")
    print("\t-n:TCP null scan")
    print("\t-u:UDP scan")
    print("\t<ip:port>:destination ip address and ports")
    print("\n\nEXAMPLE:\n\t"+sys.argv[0]+" -c 192.168.56.20:80")


FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

src_port = random.randint(1024, 65535)


def TCPConnect(ip, port):
    """
        目标端口是开放的：返回1.
        目标端口关闭，返回0
        目标端口没有任何响应，返回-1
        其他未考虑情况，返回-2
    """
    print('TCP connect scan start:')
    print('==================================================')
    tcp_connect_scan_resp = sr1(
        IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S"), timeout=2)
    if (str(type(tcp_connect_scan_resp)) == "<class 'NoneType'>"):  # no responses的情况,端口被过滤
        return -1
    elif (tcp_connect_scan_resp.haslayer(TCP)):
        if (tcp_connect_scan_resp.getlayer(TCP).flags == 0x12):  # (SYN,ACK)
            send_rst = sr(IP(dst=ip) / TCP(sport=src_port,dport=port, flags="AR"), timeout=2)  # 回复ACK,RST
            return 1
        elif (tcp_connect_scan_resp.getlayer(TCP).flags == 0x14):  # (RST,ACK)
            return 0
    else:
        return -2


def TcpStealthy(ip, port):
    """
        目标端口是开放的：返回1.
        目标端口关闭，返回0
        目标端口没有任何响应，返回-1
    """
    print("TCP stealth scan start:")

    stealth_scan_resp = sr1(IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S"), timeout=2)
    if (str(type(stealth_scan_resp)) == "<class 'NoneType'>"):
        return -1
    elif (stealth_scan_resp.haslayer(TCP)):
        if (stealth_scan_resp.getlayer(TCP).flags == 0x12):  # (SYN,ACK)
            # 只回复RST，与connect scan的区别
            #send_rst = sr(IP(dst=ip) / TCP(sport=src_port,dport=port, flags="R"), timeout=5) 
            send(IP(dst=ip)/TCP(sport=src_port,dport=port,seq=stealth_scan_resp.ack,ack=stealth_scan_resp.seq+1,flags="R"))
            return 1
        elif (stealth_scan_resp.getlayer(TCP).flags == 0x14):  # (RST,ACK)
            return 0
    elif (stealth_scan_resp.haslayer(ICMP)):
        if (int(stealth_scan_resp.getlayer(ICMP).type) == 3 and int(stealth_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]):
            return -1
        
    

def TCPFin(ip, port):
    """
       端口关闭状态，返回0
       端口开放或者过滤状态，返回1
       其他未考虑情况，返回-2
    """
    print("TCP fin scan start:")
    print('==================================================')
    fin_scan_resp = sr1(IP(dst=ip)/TCP(sport=src_port,dport=port,flags="F"),timeout=2)
    print('=================================================')

    if (str(type(fin_scan_resp))=="<class 'NoneType'>"):
        return 1
    elif(fin_scan_resp.haslayer(TCP)):
        if(fin_scan_resp.getlayer(TCP).flags == 0x14):
            return 0
    elif(fin_scan_resp.haslayer(ICMP)):
        if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return 1
    else: return -2

def TCPXmas(ip, port):
    """
        目标端口是关闭：返回0
        目标端口开放或者过滤状态，返回1
        其他未考虑情况返回-2
    """
    print("TCP Xmas scan start:")
    print('==================================================')
    
    xmas_scan_resp = sr1(IP(dst=ip) / TCP(dport=port, flags="FPU"), timeout=2)
    if (str(type(xmas_scan_resp)) == "<class 'NoneType'>"):
        return 1
    elif (xmas_scan_resp.haslayer(TCP)):
        if (xmas_scan_resp.getlayer(TCP).flags == 0x14):# (RST,ACK)
            return 0
    elif (xmas_scan_resp.haslayer(ICMP)):
        if (int(xmas_scan_resp.getlayer(ICMP).type) == 3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10,13]):
            return 1
    else:
        return -2
    



def TCPNull(ip, port):
    """
       端口关闭状态，返回0
       端口开放或者过滤状态，返回1
       其他未考虑情况，返回-2
    """
    print("TCP null scan start:")
    print('==================================================')
    null_scan_resp = sr1(IP(dst=ip)/TCP(dport=port,flags=""),timeout=2)
    if (str(type(null_scan_resp))=="<class 'NoneType'>"):
        return 1
    elif(null_scan_resp.haslayer(TCP)):
        if(null_scan_resp.getlayer(TCP).flags == 0x14):
            return 0
    elif(null_scan_resp.haslayer(ICMP)):
        if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            return 1

def UDPScan(ip, port):
    """
        端口关闭，返回0
        端口开放状态:返回1
        端口过滤状态：返回-1
        端口过滤或者开放状态，返回-2
    """
    print("UDP scan start:")
    print('==================================================')
    
    udp_scan_resp = sr1(IP(dst=ip)/UDP(sport=src_port,dport=port),timeout=2)
    
    if not udp_scan_resp:
        return -2
    if udp_scan_resp.haslayer(UDP):
        return 1
    if udp_scan_resp.haslayer(ICMP):
        if int(udp_scan_resp.getlayer(ICMP).type) ==3 and  int(udp_scan_resp.getlayer(ICMP).code)==3:
            return 0
        if int(udp_scan_resp.getlayer(ICMP).type) ==3 and  int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]:
            return -1
    else: return -2

if __name__ =="__main__":
    opts = [opt for opt in sys.argv[1:] if opt.startswith("-")] # options
    args = [arg for arg in sys.argv[1:] if not arg.startswith("-")] # ip:port

    if len(args) >1 or len(args) ==0:
        help()
        exit(1)

    dividPos = args[0].find(":")
    if(dividPos ==-1):
        print("ERROR:You did not enter a port number!")
        sys.exit(1)

    ip = args[0][:dividPos]
    port = int(args[0][dividPos+1:])
    
    if "-c" in opts:
        res = TCPConnect(ip,port)
        print('==================================================')
        if res == 0:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":CLOSED")
        elif res == 1:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":OPEN")
        else:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":FILTERED")
    
    elif "-s" in opts:
        res = TcpStealthy(ip,port)
        print('==================================================')
        if res == 0:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":CLOSED")
        elif res == 1:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":OPEN")
        elif res == -1:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":FILTERED")
    elif "-f" in opts:
        res = TCPFin(ip,port)
        print('==================================================')
        if res == 0:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":CLOSED")
        elif res == 1:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":OPREN OR FILTERED")
        else:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":unknown state")
   
    elif "-x" in opts:
        res = TCPXmas(ip,port) 

        print('==================================================')

        if res == 0:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":CLOSED")
        elif res == 1:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":OPEN OR FILTERED")
        else:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":XMAX ERROR")
    
    
    elif "-n" in opts:
        res = TCPNull(ip,port)
        print('==================================================')
        if res == 0:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":CLOSED")
        elif res == 1:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":OPEN OR FILTERED")
        else:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":unknown state")
    
    elif "-u" in opts:
        res = UDPScan(ip,port)
        print('==================================================')
        if res == 0:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":CLOSED")
        elif res == 1:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":OPEN")
        elif res ==-1:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":FILTERED")
        elif res ==-2:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":OPEN OR FILTERED")
        else:
            print('State of port ' + str(port) + ' of ' + str(ip) + ":unknown state")
    else:
        help()
        sys.exit(1)
