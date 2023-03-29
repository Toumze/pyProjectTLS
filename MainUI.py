import sys

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import *


class MainUI(QWidget):
    def __init__(self):
        super(MainUI, self).__init__(None)
        self.tshark_path = None
        self.interface = None
        self.bpf_filter = None
        self.display_filter = None
        self.file_rode = None
        self.choice_function = None
        self.setWindowTitle("TLS指纹分析")
        self.resize(800, 600)

        # 选择 tshark.exe
        self.label_pyshark = QLabel(self)
        self.label_pyshark.setGeometry(QtCore.QRect(10, 30, 75, 23))
        self.label_pyshark.setText("tshark：")
        self.lineEdit_pyshark = QLineEdit(self)
        self.lineEdit_pyshark.setGeometry(QtCore.QRect(100, 30, 180, 23))
        self.lineEdit_pyshark.setText("D:\\software\\Wireshark\\tshark.exe")
        self.button_open_pyshark = QPushButton(self)
        self.button_open_pyshark.setGeometry(QtCore.QRect(300, 30, 75, 23))
        self.button_open_pyshark.setText("选择")
        self.button_open_pyshark.clicked.connect(self.choose_tshark)

        # 选择活动接口读取
        self.button_live_capture = QPushButton(self)
        self.button_live_capture.setGeometry(QtCore.QRect(150, 100, 80, 25))
        self.button_live_capture.setText("接口读取")
        self.button_live_capture.clicked.connect(self.choose_live_capture)

        # 选择文件读取
        self.button_file_capture = QPushButton(self)
        self.button_file_capture.setGeometry(QtCore.QRect(600, 100, 80, 25))
        self.button_file_capture.setText("文件读取")
        self.button_file_capture.clicked.connect(self.choose_file_capture)
        self.lineEdit_file_capture = QLineEdit(self)
        self.lineEdit_file_capture.setGeometry(QtCore.QRect(380, 100, 200, 25))

    def choose_tshark(self):
        """
        获得 tshark 的文件位置
        :return: None
        """
        folder_path = QFileDialog.getOpenFileName(self, "选择tshark路径")[0]
        self.lineEdit_pyshark.clear()
        self.lineEdit_pyshark.setText(folder_path)

    def choose_live_capture(self):
        """
        选择活动接口读取
        :return:
        """
        self.choice_function = "live_capture"

    def choose_file_capture(self):
        """
        获得要读取 capture 文件位置
        :return:
        """
        folder_path = QFileDialog.getOpenFileName(self, "选择pcap路径")[0]
        self.lineEdit_file_capture.clear()
        self.lineEdit_file_capture.setText(folder_path)
        self.choice_function = "file_captur"


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)

    Main = MainUI()
    Main.show()

    sys.exit(app.exec_())
