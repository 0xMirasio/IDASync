import os
import json
from idasync.logging import pprint
from idasync.GUI.gui_main import Ui_MainWindow

class Manager():
    def __init__(self) -> None:
        self.gui_main_instancied = None
        r = self.checkConfig()
        if r:
            return None


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
        return 0

    def start(self):
        # do not create multiple instances
        if self.gui_main_instancied is None:
            self.gui_start = Ui_MainWindow(self)
            self.gui_start.show()
            self.gui_main_instancied = True
        else:
            self.gui_start.activateWindow()
            self.gui_start.raise_()
        
