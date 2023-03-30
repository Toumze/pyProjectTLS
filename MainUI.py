import sys

from PyQt5 import QtCore, QtWidgets
from PyQt5.QtWidgets import *
import shark
import time


class MainUI(QWidget):
    def __init__(self):
        super(MainUI, self).__init__(None)
        self.tshark_path = None
        self.interface = None
        self.bpf_filter = None
        self.display_filter = None
        self.file_rode = None
        self.choice_function = None
        self.shark = None
        self.window_width = 800
        self.window_height = 600
        self.setWindowTitle("TLS指纹分析")

        self.resize(self.window_width, self.window_height)
        self.setMinimumWidth(self.window_width)  # 设置最小窗口大小
        self.setMinimumHeight(self.window_height)
        print(self.width(), self.height())

        # 选择 tshark.exe
        self.label_tshark = QLabel(self)
        self.label_tshark.setGeometry(QtCore.QRect(30, 30, 75, 23))
        self.label_tshark.setText("tshark：")
        self.lineEdit_tshark = QLineEdit(self)
        self.lineEdit_tshark.setGeometry(QtCore.QRect(130, 30, 180, 23))
        self.lineEdit_tshark.setText("D:\\software\\Wireshark\\tshark.exe")
        self.button_open_tshark = QPushButton(self)
        self.button_open_tshark.setGeometry(QtCore.QRect(330, 30, 75, 23))
        self.button_open_tshark.setText("选择")
        self.button_open_tshark.clicked.connect(self.choose_tshark)

        # 选择活动接口读取
        self.button_live_capture = QPushButton(self)
        self.button_live_capture.setGeometry(QtCore.QRect(40, 100, 80, 25))
        self.button_live_capture.setText("接口读取")
        self.button_live_capture.clicked.connect(self.choose_live_capture)
        self.comboBox_live_interface = QComboBox(self)
        self.comboBox_live_interface.setGeometry(QtCore.QRect(130, 100, 200, 25))

        # 选择文件读取
        self.button_file_capture = QPushButton(self)
        self.button_file_capture.setGeometry(QtCore.QRect(400, 100, 80, 25))
        self.button_file_capture.setText("文件读取")
        self.button_file_capture.clicked.connect(self.choose_file_capture)
        self.lineEdit_file_capture = QLineEdit(self)
        self.lineEdit_file_capture.setGeometry(QtCore.QRect(490, 100, 200, 25))

        # 过滤规则
        self.label_display_filter = QLabel(self)
        self.label_display_filter.setGeometry(QtCore.QRect(40, 170, 90, 25))
        self.label_display_filter.setText("过滤规则:")
        self.lineEdit_display_filter = QLineEdit(self)
        self.lineEdit_display_filter.setGeometry(QtCore.QRect(130, 170, 200, 25))

        # 分割线

        # 确认按钮
        self.button_begin = QPushButton(self)
        self.button_begin.setGeometry(QtCore.QRect(500, 155, 120, 45))
        self.button_begin.setText("开始")
        self.button_begin.clicked.connect(self.begin)

        # 显示区域
        self.tableWidget_overall = QTableWidget(self)
        self.tableWidget_overall.setGeometry(QtCore.QRect(40, 210, 720, 80))

        self.tableWidget = QTableWidget(self)
        self.tableWidget.setGeometry(QtCore.QRect(40, 300, 720, 250))

    def resizeEvent(self, a0) -> None:
        self.window_height = a0.size().height()
        self.window_width = a0.size().width()
        self.reprint()

    def reprint(self):
        change = self.window_width * 1.0 / 800

        # 位置 tshark.exe
        self.label_tshark.setGeometry(QtCore.QRect(int(change * 40), 30, 75, 23))
        self.lineEdit_tshark.setGeometry(QtCore.QRect(int(change * 40) + 65, 30, 180, 23))
        self.button_open_tshark.setGeometry(QtCore.QRect(int(change * 40) + 215 + 40, 30, 75, 23))

        # 位置 活动接口读取
        self.button_live_capture.setGeometry(QtCore.QRect(int(change * 40), 100, 80, 25))
        self.comboBox_live_interface.setGeometry(QtCore.QRect(int(change * 40) + 90, 100, 200, 25))

        # 位置 选择文件读取
        self.button_file_capture.setGeometry(QtCore.QRect(int(change * 400), 100, 80, 25))
        self.lineEdit_file_capture.setGeometry(QtCore.QRect(int(change * 400) + 90, 100, 200, 25))

        # 位置 过滤规则
        self.label_display_filter.setGeometry(QtCore.QRect(int(change * 40), 170, 90, 25))
        self.lineEdit_display_filter.setGeometry(QtCore.QRect(int(change * 40) + 100, 170, 200, 25))

        # 位置 确认按钮
        self.button_begin.setGeometry(QtCore.QRect(int(change * 500), 155, 120, 45))

        # 显示区域
        self.tableWidget_overall.setGeometry(QtCore.QRect(40, 210, self.window_width - 80, 80))
        self.tableWidget.setGeometry(QtCore.QRect(40, 300, self.window_width - 80, self.window_height - 350))

    def choose_tshark(self):
        """
        获得 tshark 的文件位置
        :return: None
        """
        folder_path = QFileDialog.getOpenFileName(self, "选择tshark路径")[0]
        self.lineEdit_tshark.clear()
        self.lineEdit_tshark.setText(folder_path)

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
        self.choice_function = "file_capture"

    def begin(self):
        self.button_begin.setEnabled(False)  # 设置按钮失效
        self.button_begin.setStyleSheet('''QPushButton{background:#D3D3D3}''')
        time.sleep(0.1)
        self.tshark_path = self.lineEdit_tshark.text()
        self.display_filter = self.lineEdit_display_filter.text()
        self.interface = self.comboBox_live_interface.currentText()
        self.file_rode = self.lineEdit_file_capture.text()
        self.shark = shark.WiresharkAnalysis(tshark_path=self.tshark_path, interface=None, bpf_filter=None,
                                             keep_packets=True, display_filter=self.display_filter)
        if self.choice_function == "live_capture":
            self.shark.pyshark_live_capture(display_filter_=self.display_filter)
        elif self.choice_function == "file_capture":
            self.shark.pyshark_file_capture(file_rode=self.file_rode, display_filter_=self.display_filter)
            ja3_dict = self.shark.count_file_ja3()
            self.repaint_table(ja3_dict)
            infor = self.shark.information_()
            self.repaint_table_overall(infor)
        else:
            pass
        self.button_begin.setStyleSheet('''QPushButton{background:#FFFFFF}''')
        self.button_begin.setEnabled(True)

    def repaint_table(self, ja3_dict):
        """
        输出获得的 TLS 指纹
        :param ja3_dict: dict
        :return: None
        """
        self.tableWidget.clear()
        self.tableWidget.setRowCount(len(ja3_dict))
        self.tableWidget.setColumnCount(6)
        num_row = 0
        for item in ja3_dict:
            num_col = 0
            new_item = QTableWidgetItem(str(ja3_dict[item]))
            self.tableWidget.setItem(num_row, num_col, new_item)
            list_tls = item.split(",")
            for j in list_tls:
                num_col += 1
                new_item = QTableWidgetItem(j)
                self.tableWidget.setItem(num_row, num_col, new_item)
            num_row += 1

    def repaint_table_overall(self, info):
        self.tableWidget_overall.clear()
        self.tableWidget_overall.setRowCount(2)
        self.tableWidget_overall.setColumnCount(len(info))
        num_col = 0
        for item in info:
            new_item = QTableWidgetItem(item)
            self.tableWidget_overall.setItem(0, num_col, new_item)
            new_item = QTableWidgetItem(str(info[item]))
            self.tableWidget_overall.setItem(1, num_col, new_item)
            num_col += 1


if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)

    Main = MainUI()
    Main.show()

    sys.exit(app.exec_())
