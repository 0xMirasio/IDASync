import os
import json
import ida_nalt
from idasync.util import pprint
from idasync.GUI.gui_main import Ui_MainWindow
from PyQt5.QtCore import QObject

class Manager(QObject):

    def __init__(self) -> None:
        super(Manager, self).__init__()
        
        self.gui_running = None
        r = self.checkConfig()
        if r:
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
        
        self.version = data["version"]
        self.port = data["port"]
        self.ip = data["ip"]
        return 0

    def start(self):
        self.gui_start = Ui_MainWindow(self)
        self.gui_start.show()
            