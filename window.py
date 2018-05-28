#!/usr/bin/python3

import sys
from queue import Queue
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtCore import QThread,pyqtSignal,Qt
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtWidgets import QApplication,QGridLayout,QWidget,QMainWindow,QAction,QVBoxLayout,QSplitter
from PyQt5.QtWidgets import QTableWidget,QTableWidgetItem,QAbstractItemView,QTabWidget,QTextEdit
#from multiprocessing import Manager,Process,Queue
from time import sleep, time
#from capture import *
import utils
import traceback
from scapy.all import *

global pkt_lst
global count
global pl



class MyPacket():

    def __init__(self,packet,num):

        self.num = num
        self.packet = packet
        try:
            self.macSrc = packet.src
            self.macDst = packet.dst
            self.src = self.macSrc
            self.dst = self.macDst
        except:
            pass
        try:
            self.ipSrc=packet[IP].src
            self.ipDst=packet[IP].dst
            self.src = self.ipSrc
            self.dst = self.ipDst
        except:
            pass
        try:
            self.srcProt=str(packet[TCP].sport)
            self.dstPort=str(packet[TCP].dport)
        except:
            pass
        try:
            self.srcPort=str(packet[UDP].sport)
            self.dstPort=str(packet[UDP].dport)
        except:
            pass
        self.time = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(packet.time))
        self.len = len(packet.original)
        self.hex = packet.original.hex()
        self.hierarchical = packet.show(dump=True)
        if packet.haslayer("TCP"):
            self.pro = "TCP"
        elif packet.haslayer("UDP"):
            self.pro = "UDP"
        elif packet.haslayer("ICMP"):
            self.pro = "ICMP"
        elif packet.haslayer("ARP"):
            self.pro = "ARP"


class CaptureThread(QThread):

    def __init__(self,iface,f_str):
        super(CaptureThread,self).__init__()
        self.isRunning = True
        self.iface = iface
        self.f_str = f_str
        print("Init the capture thread")
    def run(self):
        while self.isRunning:
            print("Capture thread is running")
            global pkt_lst
            print(self.iface,self.f_str)
            try:
                sniff(iface=self.iface,filter=self.f_str,prn=redirect)
            except NameError as e:
                traceback.print_exc()
    def stop(self):
        self.isRunning = False



class ProcessThread(QtCore.QThread):

    AddPacket = pyqtSignal(list)
    Scroll = pyqtSignal(str)

    def __init__(self):
        super(ProcessThread,self).__init__()
        self.isRunning = True
        print("Init the process thread")
    def run(self):
        """
        parse packet and display in table
        """
        print("Process thread is running")
        #num=0
        global pkt_lst
        global pl
        #print(pkt_lst.empty())
        while self.isRunning:
            if not pkt_lst.empty():
                try:
                    p = pkt_lst.get()
                    pl.append(p)
                    l = [p.num,p.time,p.src,p.dst,p.len,p.pro]
                    #print(l)
                    self.AddPacket.emit(l)
                    #print("The AddPacketSignal is emit")
                except Exception as e:
                    traceback.print_exc()
                    continue
                # deal with packets
    def stop(self):
        self.isRunning = False

def redirect(packet):
    global pkt_lst
    global count
    count = count + 1
    #print(packet)
    pkt_lst.put(MyPacket(packet,count))
    #print(packet.haslayer("ARP"))



class MyMainWindow(QMainWindow):

    def __init__(self):

        super(MyMainWindow,self).__init__()

        startAction = QAction(QIcon('startbutton.png'),'Start to sniff',self)
        stopAction = QAction(QIcon('stopbutton.png'),'Stop sniffing',self)

        startAction.triggered.connect(self.slotCapture)
        startAction.triggered.connect(self.slotProcess)
        stopAction.triggered.connect(self.slotStopCap)

        self.toolBar = self.addToolBar('ToolBar')
        self.toolBar.addAction(startAction)
        self.toolBar.addAction(stopAction)

        self.setup()

    def setup(self):

        self.setWindowTitle('Sniffer')

        self.centralWidget = MyCentralWidget()
        self.setCentralWidget(self.centralWidget)
        self.resize(900,700)

    def slotCapture(self):
        print("Entered the slot of Capture")
        global count
        count = 0
        global pl
        pl = []
        global pkt_lst
        clear(pkt_lst)
        while(self.centralWidget.tableWidget.rowCount() != 0):
            self.centralWidget.tableWidget.removeRow(0)
        iface = self.centralWidget.comboBox.currentText()
        f_str = self.centralWidget.filterBar.text()
        self.capture = CaptureThread(iface,f_str)
        self.centralWidget.tableWidget.clearContents()
        print("Begin to start the Capture thread")
        self.capture.start()
    def slotStopCap(self):
        self.capture.stop()
        self.process.stop()

    def slotProcess(self):
        print("Entered the slot of process")
        self.process = ProcessThread()
        self.process.AddPacket.connect(self.AddPacketToTable)
        print("Begin to start the Process thread")
        self.process.start()

    def closeEvent(self,event):
        quit()
    def AddPacketToTable(self,l):
        #print("AddPacketToTable")
        num = l[0]
        rc = self.centralWidget.tableWidget.rowCount()
        self.centralWidget.tableWidget.setRowCount(rc + 1)

        for i in range(len(l)):
            item = QTableWidgetItem(str(l[i]))
            #print(l[i])
            #print(item)
            self.centralWidget.tableWidget.setItem(rc,i,item)




class MyCentralWidget(QWidget):

    def __init__(self):

        super(MyCentralWidget,self).__init__()
        self.setup()

    def setup(self):

        self.vLayout = QtWidgets.QVBoxLayout()
        self.gridLayout = QtWidgets.QGridLayout()
        self.gridLayout.setContentsMargins(0,0,0,0)

        ###### Line 1 #####
        self.lableIface = QtWidgets.QLabel()
        self.lableIface.setText("Interface List")

        ifaceList = utils.getIfaceList()

        self.comboBox = QtWidgets.QComboBox()
        for i in ifaceList:
            self.comboBox.addItem(i)

        self.gridLayout.addWidget(self.lableIface,0,0,1,1)
        self.gridLayout.addWidget(self.comboBox,0,1,1,7)

        ###### Line 2 #####

        self.lableFilter = QtWidgets.QLabel()
        self.lableFilter.setText("Filter")

        self.filterBar = QtWidgets.QLineEdit()
        self.filterBar.setFixedHeight(30)
        self.filterBar.setClearButtonEnabled(True)


        self.gridLayout.addWidget(self.lableFilter,1,0,1,1)
        self.gridLayout.addWidget(self.filterBar,1,1,1,7)


        ###### Detail Information of Captured Packets #####

        ###### Packets List ######

        self.tableWidget = QTableWidget()
        self.tableWidget.setFont(QFont("monospace",12));
        self.tableWidget.verticalHeader().setDefaultSectionSize(25)
        #self.tableWidget.horizontalHeader().setFont(QFont('Consolas', 11, QFont.Light))
        self.tableWidget.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.tableWidget.setColumnCount(6)
        self.tableWidget.verticalHeader().setVisible(False)
        self.tableWidget.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        self.tableWidget.setHorizontalHeaderLabels(
             ['No.', 'Time', 'Source address', 'Destination address', 'Length', 'Protocol'])
        self.tableWidget.setColumnWidth(0, 60)
        self.tableWidget.setColumnWidth(1, 100)
        self.tableWidget.setColumnWidth(2, 240)
        self.tableWidget.setColumnWidth(3, 240)
        self.tableWidget.setColumnWidth(4, 75)
        self.tableWidget.setColumnWidth(5, 90)
        self.tableWidget.setEditTriggers(QAbstractItemView.NoEditTriggers)

        self.tableWidget.setSelectionBehavior(QTableWidget.SelectRows)
        self.tableWidget.setSelectionMode(QTableWidget.SingleSelection)
        self.tableWidget.itemSelectionChanged.connect(self.EvtSelect)

        ###### Frame Information ######
        self.tabWidget1 = QTabWidget()
        self.tabWidget1.setMinimumHeight(50)

        self.tabWidget2 = QTabWidget()
        self.tabWidget2.setMinimumHeight(50)

        ###### Use splitter to put three block together ######
        splitter = QSplitter(Qt.Vertical)
        splitter.addWidget(self.tableWidget)
        splitter.addWidget(self.tabWidget1)
        splitter.addWidget(self.tabWidget2)
        splitter.setSizes([200, 200, 200])


        self.gridLayout.addWidget(splitter,2,0,5,7)
        #self.gridLayout.setRowMinimumHeight(3, 690)
        self.vLayout.addLayout(self.gridLayout)


        self.setLayout(self.vLayout)

    def EvtSelect(self):
        QtCore.QCoreApplication.processEvents()
        for i in self.tableWidget.selectedItems():
            row = i.row()

        for i in range(self.tabWidget1.count()):
            self.tabWidget1.removeTab(0)
        for i in range(self.tabWidget2.count()):
            self.tabWidget2.removeTab(0)
        global pl
        content = QTextEdit()
        self.tabWidget1.addTab(content,"content")
        content.setText(pl[row].hierarchical)

        content_hex = QTextEdit()
        self.tabWidget2.addTab(content_hex,"content hex")
        content_hex.setText(pl[row].hex)

def clear(queue):
    while not queue.empty():
        queue.get()

import pdb
#pdb.set_trace()
def main():

    global pl
    pl = []
    global pkt_lst
    pkt_lst = Queue()
    global count
    count = 0

    app = QApplication(sys.argv)
    mainWindow = MyMainWindow()
    mainWindow.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()

