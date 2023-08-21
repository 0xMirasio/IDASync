from PyQt5 import QtCore, QtGui, QtWidgets
import ida_kernwin
import idaapi

class Ui_MainWindow(QtWidgets.QMainWindow):
    
    def __init__(self, manager):
        parent = idaapi.PluginForm.FormToPyQtWidget(ida_kernwin.get_current_widget())
        super().__init__(parent)
        self.manager = manager
        self.setupUi()
        self.setupAction()
        self.setupLabel()

    def setupUi(self):
        self.setObjectName("IDASync")
        self.resize(1632, 837)
        self.centralwidget = QtWidgets.QWidget(self)
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(10, 20, 1571, 771))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.l_p_ver = QtWidgets.QLabel(self.tab)
        self.l_p_ver.setGeometry(QtCore.QRect(10, 20, 141, 21))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.l_p_ver.setFont(font)
        self.l_p_ver.setObjectName("l_p_ver")
        self.l_v_ver = QtWidgets.QLabel(self.tab)
        self.l_v_ver.setGeometry(QtCore.QRect(160, 20, 151, 21))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.l_v_ver.setFont(font)
        self.l_v_ver.setObjectName("l_v_ver")
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_5 = QtWidgets.QWidget()
        self.tab_5.setObjectName("tab_5")
        self.tabWidget.addTab(self.tab_5, "")
        self.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(self)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1632, 22))
        self.menubar.setObjectName("menubar")
        self.menuExit = QtWidgets.QMenu(self.menubar)
        self.menuExit.setObjectName("menuExit")
        self.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(self)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)
        self.menubar.addAction(self.menuExit.menuAction())

        self.retranslateUi()
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self):
        _translate = QtCore.QCoreApplication.translate
        self.setWindowTitle(_translate("IDASync", "IDASync"))
        self.l_p_ver.setText(_translate("IDASync", "IDASync Version :"))
        self.l_v_ver.setText(_translate("IDASync", "{version}"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("IDASync", "IDASync"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("IDASync", "Options"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_5), _translate("IDASync", "Information"))
        self.menuExit.setTitle(_translate("IDASync", "Exit"))

    def setupLabel(self):
        self.l_v_ver.setText(self.manager.version)

    def setupAction(self):
        self.menuExit.aboutToShow.connect(self.close)
