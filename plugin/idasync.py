import idaapi
import ida_kernwin
import os

from idasync.util import pprint
from idasync.manager import Manager

idaapi.require("idasync.GUI.gui_main")

# IDASync plugin
class IDASyncPlugin(idaapi.plugin_t):
    IDAPluginsName = "IdaSync"
    flags = idaapi.PLUGIN_MOD
    comment = "IDASync plugin"
    wanted_name = IDAPluginsName
    help = "IDA Instance Synchronization PLugin"
    wanted_hotkey = "Ctrl+Alt+F3"

    
    def init(self) -> idaapi.plugmod_t:
        print('************** IDASync | Thibault Poncetta *****************')
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        pprint("Plugin Running")
        manager = Manager()
        if not manager:
            return -1

        manager.start()      

    def term(self):
        pass


def PLUGIN_ENTRY() -> idaapi.plugin_t:
    return IDASyncPlugin()

