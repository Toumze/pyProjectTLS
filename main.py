import shark
import sys
import MainUI
from PyQt5 import QtWidgets


if __name__ == '__main__':

    num = input("please input choice: ")
    if num == "1":
        app = QtWidgets.QApplication(sys.argv)

        Main = MainUI.MainUI()

        sys.exit(app.exec_())
        pass


    else:
        print("----- begin the test11.py -----")

        test_shark = shark.WiresharkAnalysis(tshark_path="D:\\software\\Wireshark\\tshark.exe", interface=None,
                                             bpf_filter=None, keep_packets=True,
                                             display_filter="(tls.handshake.type == 1 or tls.handshake.type == 2) and ip.src != "
                                                            "127.0.0.1")
        test_shark.pyshark_file_capture(file_rode="D:\周报\抓包\\google.pcapng",
                                        display_filter_="(tls.handshake.type == 1 or tls.handshake.type == 2) and ip.src != 127.0.0.1")
        print("--init end--")
        test_shark.count_file_ja3()
        print("----- end of test11.py -----")
