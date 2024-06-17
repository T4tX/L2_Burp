# Import necessary modules
from PyQt6 import QtWidgets, uic
from PyQt6 import QtGui
from PyQt6.QtCore import *
import netifaces
from netfilterqueue import NetfilterQueue
from scapy.all import *
import threading
import queue

def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x

# Define SniffThread class
class SniffThread(QThread):
    output = pyqtSignal(object)  # Define signal for output

    def __init__(self, main_window, pkt_buffer):
        QThread.__init__(self)
        self.mainWindow = main_window
        self.interface = ''
        self.filter_text = ''
        self.buffer = pkt_buffer
        self.stop = False

    def render(self, interface, filter_text):
        self.interface = interface
        self.filter_text = filter_text
        self.start()

    def run(self):
        try:
            self.mainWindow.running_info.setText("Sniffing... by thread No. " + str(self.currentThreadId()))
            sniff(filter=self.filter_text, 
                iface=self.interface, 
                prn=self.print_summary,
                stop_filter=lambda x: self.stop)
            self.mainWindow.running_info.setText("Ready to sniff")
        except Exception as e:
            self.mainWindow.running_info.setText("Terminated due to Error: " + str(e))

    def halt(self):
        self.stop = True

    def print_summary(self, pkt):
        # Process packet summary and emit signal
        pkt_list = list(expand(pkt))
        time = datetime.fromtimestamp(pkt.time)
        info = pkt.summary()
        protocol = None
        src = None
        dst = None
        try:
            length = pkt.len
        except:
            length = None
        for i in range(len(pkt_list)):
            # TODO: parse HTTP protocol
            if pkt_list[i].name not in ['Raw', 'Padding']:
                protocol = pkt_list[i].name
            try:
                src = pkt_list[i].src
                dst = pkt_list[i].dst
            except:
                pass
        self.buffer.append(pkt)
        l = [str(time), str(src), str(dst), str(protocol), str(length), str(info)]
        self.output.emit(l)

class ProxyThread(QThread):
    output = pyqtSignal(object)  # Define signal for output

    def __init__(self, main_window, proxy_loop):
        QThread.__init__(self)
        self.mainWindow = main_window
        self.nfqueue = None
        self.s = None
        self.stop = False 
        self.accept_packets = None 
        self.proxy_loop = proxy_loop

    def set_nfqueue(self):
        os.system('sysctl net.ipv4.ip_forward=1')
        os.system('iptables -A OUTPUT -j NFQUEUE --queue-num 1')

    def unset_nfqueue(self):
        os.system('sysctl net.ipv4.ip_forward=0')
        os.system('iptables -F')

    def run(self):
        self.set_nfqueue()
        self.nfqueue = NetfilterQueue()
        self.nfqueue.bind(1, self.callback)
        self.s = socket.fromfd(self.nfqueue.get_fd(), socket.AF_UNIX, socket.SOCK_STREAM)
        self.nfqueue.run_socket(self.s)
        while not self.stop:
            time.sleep(0.1)  # Keep the thread running until halted

    def halt(self):
        self.stop = True
        self.s.close()
        self.nfqueue.unbind()
        self.unset_nfqueue()

    def callback(self, payload):
        data = payload.get_payload()
        pkt = IP(data)
        print(pkt.summary())
        # self.output.emit(pkt)  # Emit the signal
        self.proxy_loop.put(pkt.command())


class Ui(QtWidgets.QMainWindow):
    def __init__(self):
        super(Ui, self).__init__()
        uic.loadUi('pyqt_1.1.ui', self)
        self.show()
        self.set_options()
        self.pkt_buffer = []
        self.repeater_buffer = []
        self.filter_table.cellClicked.connect(self.show_detail)
        self.filterButton.clicked.connect(self.start_thread)
        self.haltButton.clicked.connect(self.halt_thread)
        self.to_repeater.clicked.connect(self.add_to_repeater)
        self.tabWidget.currentChanged.connect(self.onTabChanged)
        self.repeater_array.currentIndexChanged.connect(self.onRepeaterChange)
        self.send.clicked.connect(self.onRepeaterSendClick)
        self.sendp.clicked.connect(self.onRepeaterSendpClick)

        self.proxy_start.clicked.connect(self.onProxyStart)
        self.proxy_stop.clicked.connect(self.onProxyStop)
        self.proxy_accept.clicked.connect(self.onProxyAccept)
        self.proxy_drop.clicked.connect(self.onProxyDrop)
        self.running_info.setText("Ready to sniff")
        self.thread = None
        self.proxy_thread = None
        self.event = threading.Event()
        self.proxy_loop = queue.Queue()


    def onProxyStart(self):
        if self.proxy_thread is not None and self.proxy_thread.isRunning():
            self.proxy_status.setText('Please wait for the ending of the last thread and Try it again')
        else:
            self.proxy_text.clear()
            self.proxy_thread = ProxyThread(self, self.proxy_loop)
            # self.thread.output.connect(self.push_entry)  # Connect signal to slot
            self.proxy_thread.start() 
    # def on_proxy_output(self, proxy_pkt):
    #     self.proxy_text.setPlainText(proxy_pkt) 
    def onProxyStop(self):
        self.proxy_thread.halt()
        if not self.proxy_loop.empty():
            pkt = self.proxy_loop.get()
            self.proxy_text.setPlainText(pkt)
        else:
            self.proxy_status.setText('Empty queque')
    def onProxyAccept(self):
        # self.event.set()
        if not self.proxy_loop.empty():
            pkt = self.proxy_text.toPlainText()
            try:
                sendp(pkt)
            except Exception as e:
                self.proxy_status.setText(str(e))
            finally:
                pkt = self.proxy_loop.get()
                self.proxy_text.setPlainText(pkt)
                self.proxy_status.setText('All right!')

        else:
            self.proxy_status.setText('Empty queque')
        # pkt = self.proxy_text.toPlainText()
    def onProxyDrop(self):
        if not self.proxy_loop.empty():
            pkt = self.proxy_loop.get()
            self.proxy_text.setPlainText(pkt)
        else:
            self.proxy_status.setText('Empty queque')
    # def proxy_push_entry(self, proxy_pkt):
    #     print(proxy_pkt)

    def onTabChanged(self, index):
        # Обновление содержимого вкладки 2 при переходе на неё
        if index == 1:  # индекс 1 соответствует вкладке 2
            self.repeater_array.addItems([i.summary() for i in self.repeater_buffer])
    def add_to_repeater(self):
        row = self.filter_table.currentRow()
        pkt = self.pkt_buffer[row]
        self.repeater_buffer.append(pkt)
    def onRepeaterSendpClick(self):
        pkt = self.text_send.toPlainText()
        sendp(pkt)
        self.status.setText(f'{self.repeater_array.currentText()} sucsessfully send')

    def onRepeaterSendClick(self):
        pkt = self.text_send.toPlainText()
        send(pkt)
        self.status.setText(f'{self.repeater_array.currentText()} sucsessfully send')
    def onRepeaterChange(self,index):
        pkt = self.repeater_buffer[index]
        self.text_send.setPlainText(pkt.command())


    def set_options(self):
        l = netifaces.interfaces()
        self.interface_2.addItems(l)
        header = self.filter_table.horizontalHeader()       
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(4, QtWidgets.QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QtWidgets.QHeaderView.ResizeMode.Stretch)
    def show_detail(self,row, col):
        self.detail_widget.clear()
        self.filter_table.selectRow(row)
        pkt = self.pkt_buffer[row]
        line = pkt.command() + '\n'
        self.detail_widget.addItem(line)
        text = line.split('/')
        for i in text:
            self.detail_widget.addItem(i)


    def start_thread(self):
        if self.thread is not None and self.thread.isRunning():
            self.running_info.setText('Please wait for the ending of the last thread and Try it again')
        else:
            text = str(self.filterText.text())
            interface = str(self.interface_2.currentText())
            self.pkt_buffer = []
            self.filter_table.setRowCount(0)
            self.detail_widget.clear()
            self.thread = SniffThread(self, self.pkt_buffer)
            self.thread.output.connect(self.push_entry)  # Connect signal to slot
            self.thread.render(interface=interface, filter_text=text)

    def halt_thread(self):
        self.thread.halt()

    def push_entry(self, l):
        row = self.filter_table.rowCount()
        self.filter_table.insertRow(row)
        if len(self.filter_table.selectedItems()) == 0:
            self.filter_table.scrollToBottom()
        self.filter_table.setItem(row, 0, QtWidgets.QTableWidgetItem(l[0]))
        self.filter_table.setItem(row, 1, QtWidgets.QTableWidgetItem(l[1]))
        self.filter_table.setItem(row, 2, QtWidgets.QTableWidgetItem(l[2]))
        self.filter_table.setItem(row, 3, QtWidgets.QTableWidgetItem(l[3]))
        self.filter_table.setItem(row, 4, QtWidgets.QTableWidgetItem(l[4]))
        self.filter_table.setItem(row, 5, QtWidgets.QTableWidgetItem(l[5]))
    

    
if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)
    window = Ui()
    app.exec()