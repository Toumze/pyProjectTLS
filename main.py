import sys
import MainUI
from PyQt5 import QtWidgets

if __name__ == '__main__':
    app = QtWidgets.QApplication(sys.argv)

    Main = MainUI.MainUI()
    Main.show()

    sys.exit(app.exec_())
