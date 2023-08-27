from PyQt5 import QtCore, QtGui, QtWidgets
import ida_kernwin
import idaapi


from idasync.logging import pprint
from idasync.rpcclient import Client
from PyQt5.QtCore import QTimer

class Ui_MainWindow(QtWidgets.QMainWindow):
    
    def __init__(self, manager):
        parent = idaapi.PluginForm.FormToPyQtWidget(ida_kernwin.get_current_widget())
        super().__init__(parent)
        self.manager = manager
        self.client = Client()
        
        self.console_ = ["UI_Initialised_OK"]
        self.timer = QTimer(self)

        self.setupUi(self)
        self.setupAction()
        self.setupLabel()

        self.is_server_connected = False

        self.timer.start(30000) #update every 30s


    def setupLabel(self):
        self.l_v_ver.setText(self.manager.version)
        self.l_v_serv_status.setText("Disconnected")

        self.instance_select.addItem("No instance found")

        self.le_v_ip.setText(self.manager.ip)
        self.le_v_port.setText(str(self.manager.port))

        self.update_console()

    def update_console(self):
        tt_console = ""
        for item in self.console_:
            tt_console += item + "\n"

        self.p_console.setText(tt_console)

    def closeEvent(self, event):
        (ret, err) = self.client.disconnect_instance(self.manager.name_instance)
        if ret:
            pprint(f"Failed to close instance : {err}")
        event.accept()

    def toConsole(self, msg):
        self.console_.append(msg)
        self.update_console()

    def updateInstance(self, instances):
        self.instance_select.clear()

        if len(instances) == 0:
            self.instance_select.addItem("No instance found")
            return

        for instance in instances:
            self.instance_select.addItem(instance)

    def get_instance(self):
        (ret, err, instances) = self.client.get_instance()
        if ret:
            self.toConsole(f"Couldn't get connected instances of Server : {err}")
            self.progressBar.setValue(0)

        self.updateInstance(instances)
        self.l_v_instance.setText(str(len(instances)))

    def connectRPC(self):

        self.progressBar.setValue(10)

        (ret, err) = self.client.ping()
        if ret:
            self.toConsole(f"Couldn't connect to Server : {err}")
            self.toConsole("You can run server with : \npython3 -m idasync runserver")
            self.progressBar.setValue(0)      
            return -1
        
        self.progressBar.setValue(20)
        self.toConsole("Ping Server : Sucess")


        (ret, err) = self.client.register_instance(self.manager.name_instance)
        if ret:
            self.toConsole(f"Couldn't register instance to Server : {err}")
            self.progressBar.setValue(0)
            return -1
        
        self.progressBar.setValue(30)
        self.toConsole("Register Instance to Server : Sucess")

        ret = self.get_instance()
        if ret:
            return -1
        
        self.toConsole("Get Instances from Server : Sucess")

        self.l_v_serv_status.setText("Connected")
        self.progressBar.setValue(100)
        self.is_server_connected = True

    def update_(self):
        if self.is_server_connected == False:
            return
        
        self.get_instance()


    def setupAction(self):
        self.menuExit.aboutToShow.connect(self.close)
        self.b_connect.clicked.connect(self.connectRPC)
        self.timer.timeout.connect(self.update_)

    def setupUi(self, IDASync):
        IDASync.setObjectName("IDASync")
        IDASync.resize(1632, 837)
        IDASync.setAutoFillBackground(False)
        self.centralwidget = QtWidgets.QWidget(IDASync)
        self.centralwidget.setObjectName("centralwidget")
        self.main_ = QtWidgets.QTabWidget(self.centralwidget)
        self.main_.setEnabled(True)
        self.main_.setGeometry(QtCore.QRect(20, 20, 1571, 771))
        self.main_.setObjectName("main_")
        self.main_idasync = QtWidgets.QWidget()
        self.main_idasync.setObjectName("main_idasync")
        self.l_p_ver = QtWidgets.QLabel(self.main_idasync)
        self.l_p_ver.setGeometry(QtCore.QRect(10, 20, 141, 21))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.l_p_ver.setFont(font)
        self.l_p_ver.setObjectName("l_p_ver")
        self.l_v_ver = QtWidgets.QLabel(self.main_idasync)
        self.l_v_ver.setGeometry(QtCore.QRect(160, 20, 261, 21))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.l_v_ver.setFont(font)
        self.l_v_ver.setObjectName("l_v_ver")
        self.p_console = QtWidgets.QTextEdit(self.main_idasync)
        self.p_console.setGeometry(QtCore.QRect(10, 80, 301, 621))
        self.p_console.setObjectName("p_console")
        self.b_connect = QtWidgets.QPushButton(self.main_idasync)
        self.b_connect.setGeometry(QtCore.QRect(400, 90, 261, 101))
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        self.b_connect.setFont(font)
        self.b_connect.setObjectName("b_connect")
        self.l_p_serv_status = QtWidgets.QLabel(self.main_idasync)
        self.l_p_serv_status.setGeometry(QtCore.QRect(400, 210, 71, 21))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.l_p_serv_status.setFont(font)
        self.l_p_serv_status.setObjectName("l_p_serv_status")
        self.l_v_serv_status = QtWidgets.QLabel(self.main_idasync)
        self.l_v_serv_status.setGeometry(QtCore.QRect(480, 210, 181, 21))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.l_v_serv_status.setFont(font)
        self.l_v_serv_status.setObjectName("l_v_serv_status")
        self.sync_ = QtWidgets.QTabWidget(self.main_idasync)
        self.sync_.setGeometry(QtCore.QRect(760, 40, 781, 621))
        palette = QtGui.QPalette()
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Active, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(0, 255, 0))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Inactive, QtGui.QPalette.Window, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Base, brush)
        brush = QtGui.QBrush(QtGui.QColor(255, 255, 255))
        brush.setStyle(QtCore.Qt.SolidPattern)
        palette.setBrush(QtGui.QPalette.Disabled, QtGui.QPalette.Window, brush)
        self.sync_.setPalette(palette)
        self.sync_.setAutoFillBackground(False)
        self.sync_.setTabShape(QtWidgets.QTabWidget.Triangular)
        self.sync_.setObjectName("sync_")
        self.sync_struct = QtWidgets.QWidget()
        self.sync_struct.setObjectName("sync_struct")
        self.sync_.addTab(self.sync_struct, "")
        self.sync_enums = QtWidgets.QWidget()
        self.sync_enums.setObjectName("sync_enums")
        self.sync_.addTab(self.sync_enums, "")
        self.progressBar = QtWidgets.QProgressBar(self.main_idasync)
        self.progressBar.setGeometry(QtCore.QRect(400, 240, 291, 31))
        self.progressBar.setProperty("value", 0)
        self.progressBar.setObjectName("progressBar")
        self.instance_select = QtWidgets.QComboBox(self.main_idasync)
        self.instance_select.setGeometry(QtCore.QRect(410, 370, 231, 41))
        self.instance_select.setObjectName("instance_select")
        self.l_p_instance = QtWidgets.QLabel(self.main_idasync)
        self.l_p_instance.setGeometry(QtCore.QRect(330, 300, 301, 21))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.l_p_instance.setFont(font)
        self.l_p_instance.setObjectName("l_p_instance")
        self.l_v_instance = QtWidgets.QLabel(self.main_idasync)
        self.l_v_instance.setGeometry(QtCore.QRect(640, 300, 61, 21))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.l_v_instance.setFont(font)
        self.l_v_instance.setObjectName("l_v_instance")
        self.l_p_select_instance = QtWidgets.QLabel(self.main_idasync)
        self.l_p_select_instance.setGeometry(QtCore.QRect(410, 340, 281, 21))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.l_p_select_instance.setFont(font)
        self.l_p_select_instance.setObjectName("l_p_select_instance")
        self.sync_.raise_()
        self.l_p_ver.raise_()
        self.l_v_ver.raise_()
        self.p_console.raise_()
        self.b_connect.raise_()
        self.l_p_serv_status.raise_()
        self.l_v_serv_status.raise_()
        self.progressBar.raise_()
        self.instance_select.raise_()
        self.l_p_instance.raise_()
        self.l_v_instance.raise_()
        self.l_p_select_instance.raise_()
        self.main_.addTab(self.main_idasync, "")
        self.main_opt = QtWidgets.QWidget()
        self.main_opt.setObjectName("main_opt")
        self.l_p_ip = QtWidgets.QLabel(self.main_opt)
        self.l_p_ip.setGeometry(QtCore.QRect(20, 20, 121, 21))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.l_p_ip.setFont(font)
        self.l_p_ip.setObjectName("l_p_ip")
        self.le_v_ip = QtWidgets.QTextEdit(self.main_opt)
        self.le_v_ip.setGeometry(QtCore.QRect(150, 20, 171, 21))
        self.le_v_ip.setObjectName("le_v_ip")
        self.l_p_port = QtWidgets.QLabel(self.main_opt)
        self.l_p_port.setGeometry(QtCore.QRect(20, 50, 121, 21))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.l_p_port.setFont(font)
        self.l_p_port.setObjectName("l_p_port")
        self.le_v_port = QtWidgets.QTextEdit(self.main_opt)
        self.le_v_port.setGeometry(QtCore.QRect(150, 50, 171, 21))
        self.le_v_port.setObjectName("le_v_port")
        self.b_update_config = QtWidgets.QPushButton(self.main_opt)
        self.b_update_config.setGeometry(QtCore.QRect(550, 510, 261, 101))
        font = QtGui.QFont()
        font.setPointSize(16)
        font.setBold(True)
        self.b_update_config.setFont(font)
        self.b_update_config.setObjectName("b_update_config")
        self.main_.addTab(self.main_opt, "")
        self.main_info = QtWidgets.QWidget()
        self.main_info.setObjectName("main_info")
        self.l_p_author_2 = QtWidgets.QLabel(self.main_info)
        self.l_p_author_2.setGeometry(QtCore.QRect(570, 250, 471, 21))
        font = QtGui.QFont()
        font.setPointSize(12)
        font.setBold(True)
        self.l_p_author_2.setFont(font)
        self.l_p_author_2.setObjectName("l_p_author_2")
        self.main_.addTab(self.main_info, "")
        IDASync.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(IDASync)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 1632, 22))
        self.menubar.setObjectName("menubar")
        self.menuExit = QtWidgets.QMenu(self.menubar)
        self.menuExit.setObjectName("menuExit")
        IDASync.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(IDASync)
        self.statusbar.setObjectName("statusbar")
        IDASync.setStatusBar(self.statusbar)
        self.menubar.addAction(self.menuExit.menuAction())

        self.retranslateUi(IDASync)
        self.main_.setCurrentIndex(0)
        self.sync_.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(IDASync)

    def retranslateUi(self, IDASync):
        _translate = QtCore.QCoreApplication.translate
        IDASync.setWindowTitle(_translate("IDASync", "IDASync"))
        self.l_p_ver.setText(_translate("IDASync", "IDASync Version :"))
        self.l_v_ver.setText(_translate("IDASync", "version"))
        self.b_connect.setText(_translate("IDASync", "Connect to IDASync"))
        self.l_p_serv_status.setText(_translate("IDASync", "Status : "))
        self.l_v_serv_status.setText(_translate("IDASync", "serv_status"))
        self.sync_.setTabText(self.sync_.indexOf(self.sync_struct), _translate("IDASync", "Structure"))
        self.sync_.setTabText(self.sync_.indexOf(self.sync_enums), _translate("IDASync", "Enums"))
        self.l_p_instance.setText(_translate("IDASync", "Number of IDA instances connected : "))
        self.l_v_instance.setText(_translate("IDASync", "0"))
        self.l_p_select_instance.setText(_translate("IDASync", "Select Instance To Sync Data : "))
        self.main_.setTabText(self.main_.indexOf(self.main_idasync), _translate("IDASync", "IDASync"))
        self.l_p_ip.setText(_translate("IDASync", "Listening ON :"))
        self.l_p_port.setText(_translate("IDASync", "Port : "))
        self.b_update_config.setText(_translate("IDASync", "Update CONFIG"))
        self.main_.setTabText(self.main_.indexOf(self.main_opt), _translate("IDASync", "Options"))
        self.l_p_author_2.setText(_translate("IDASync", "Bug ? Report at thibault.poncetta@gmail.com"))
        self.main_.setTabText(self.main_.indexOf(self.main_info), _translate("IDASync", "Information"))
        self.menuExit.setTitle(_translate("IDASync", "Exit"))