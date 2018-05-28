import pcap
import dpkt
from scapy.all import *
import psutil
import traceback
import time

def getIfaceList():
    netcard_info = []
    info = psutil.net_if_addrs()
    for k,v in info.items():
        #print(k,v)
        for item in v:
            if item[0] == 2 and not item[1]=='127.0.0.1':
                netcard_info.append(k)
    print(netcard_info)
    return netcard_info


def getFilter():
    f_str = ""
    return f_str

def getIface():
    iface_list = []
    return iface_list


def capture(signal,pkt_lst):
    while(signal['close'] == False):
        sleep(0.1)
        if(signal['start']==True and signal['error']==False):
            f_str = getFilter()
            iface = getIface()
            try:
                a = sniff(iface=iface,filter=f_str)
            except Exception as e:
                signal['error'] == True
                traceback.print_exc()
    return a

def captureByPypcap(iface,f_str=''):
    sniff = pcap.pcap(iface,1)
    if not f_str:
        sniff.setfilter(f_str)
    for ts,pkt in sniff:
        print(ts)
        print(pkt)


def ts2LocalTime(ts):
    time_local = time.localtime(ts)
    dt = time.strftime("%H:%M:%S",time_local)
    return dt

def main():
    getIfaceList()
    #capture('wlan0')

if __name__ == "__main__":
    main()





