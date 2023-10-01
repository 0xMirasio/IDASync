import idaapi
import ida_kernwin
import os

from idasync.util import pprint
from idasync.manager import Manager

idaapi.require("idasync.GUI.gui_main")

# IDASync plugin
class IDASyncPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MOD | idaapi.PLUGIN_PROC  # | idaapi.PLUGIN_HIDE
    comment = "IDASync plugin"
    wanted_name = "IDASync"
    help = "IDA Instance Synchronization PLugin"
    wanted_hotkey = "Ctrl+Alt+F3"
    flags = idaapi.PLUGIN_UNL

    
    def init(self) -> idaapi.plugmod_t:
        print('************** IDASync | Thibault Poncetta *****************')
        self.gui_main_instancied = False
        return idaapi.PLUGIN_KEEP

    def run(self, args):
        pprint("Plugin Running")
        manager = Manager(self.gui_main_instancied)
        if not manager:
            return -1

        manager.start()      
        self.gui_main_instancied = True

    def term(self):
        pass

class IDASyncHook(ida_kernwin.UI_Hooks):
    """
    this class is only used to install the icon to the corresponding IDA action
    """
    def __init__(self, cb):
        super().__init__()
        self.cb = cb

    def updated_actions(self):
        if self.cb():
            self.unhook()


def install_icon():
    plugin_name = "IDASync"
    action_name = "Edit/Plugins/" + plugin_name
    LOGO_PATH = None

    if action_name not in ida_kernwin.get_registered_actions():
        return False

    for plugin_path in idaapi.get_ida_subdirs("plugins"):
        LOGO_PATH = os.path.join(
            plugin_path, f"idasync\\ressources\\sync.png")

        if os.path.isfile(LOGO_PATH):
            break

    if LOGO_PATH is None:
        return True

    icon = idaapi.load_custom_icon(LOGO_PATH, format="png")
    ida_kernwin.update_action_icon(action_name, icon)
    return True



def PLUGIN_ENTRY() -> idaapi.plugin_t:
    return IDASyncPlugin()

h = IDASyncHook(install_icon)
h.hook()
