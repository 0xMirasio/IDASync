import os
import json
import ida_nalt
from idasync.util import pprint
from idasync.GUI.gui_main import Ui_MainWindow
from PyQt5.QtCore import QObject

class Manager(QObject):

    def __init__(self) -> None:
        super(Manager, self).__init__()
        
        config_ret = self.checkConfig()
        if config_ret:
            return None
        
        self.name_instance = ida_nalt.get_root_filename()

    def checkConfig(self):
        if os.name == "posix":
            cache_dir = os.path.expandvars("/$HOME/.idasync/")
        elif os.name == "nt":
            cache_dir = os.path.expandvars("%APPDATA%/IDASync/")
        else:
            return 1
        
        config = os.path.join(cache_dir, "config.json")
        if not os.path.exists(config):
            pprint("Config file not found: %s" % config)
            return 1
        
        with open(config, 'r') as file:
            data = json.load(file)
        
        self.version = data.get("version")
        assert self.version
        
        self.port = data.get("port", 4446)
        self.ip = data.get("ip", "127.0.0.1")
        self.update_time = data.get("update_time", 3000)
        return 0

    def start(self):
        self.gui_start = Ui_MainWindow(self)
        self.gui_start.show()
            