from idasync.idascripts.struct import scripts_get_structures,script_import_structure
from idasync.idascripts.enum import scripts_get_enums,scripts_import_enum
from idasync.idascripts.symbols import scripts_get_symbols,scripts_import_symbol
from idasync.api_wrapper import *
from idasync.util import toConsole,pprint
from idasync.apiclient import Client

import os
import json

class Core(object):
    def __init__(self, QtUI) -> None:
        self.ui = QtUI

    # main method called when user connect to server
    def connectRPC(self) -> int:

        self.ui.progressBar.setValue(5)

        #### PING
        ret = ping(self.ui)
        if ret:
            self.ui.progressBar.setValue(0)     
            return -1
        toConsole(self.ui, "Ping Server : ✔️")

        ### REGISTER CLIENT INSTANCE
        ret = register_instance(self.ui, self.ui.manager.name_instance)
        if ret:
            self.ui.progressBar.setValue(0)
            return -1
        
        self.ui.is_server_connected = True
        self.ui.progressBar.setValue(15)
        toConsole(self.ui, "Register Instances to Server : ✔️")
        
        #### GET SERVER INSTANCES
        instances = get_instance(self.ui)
        if len(instances) == 0:
            self.ui.progressBar.setValue(0)
            return -1
        self.ui.progressBar.setValue(20)
        toConsole(self.ui, "Get Instances from Server : ✔️")
        
        self.updateInstance(instances)
        self.ui.l_v_instance.setText(str(len(instances)))

        #### STRUCTURES CURRENT REGISTER 
        all_structures = scripts_get_structures()
        ret = register_structure(self.ui, all_structures, self.ui.manager.name_instance)
        if ret:
            self.ui.progressBar.setValue(0)
            return -1
        self.ui.progressBar.setValue(25)
        toConsole(self.ui, "Register structures to Server : ✔️")

        #### STRUCTURES SERVER GET 
        for instance in instances:
            structs = get_structure(self.ui, instance)
            if len(structs) > 0:
                self.ui.structs_all[instance] = structs
            
        if self.ui.manager.name_instance in self.ui.structs_all:    
            self.updateStructures(self.ui.structs_all[self.ui.manager.name_instance], self.ui.manager.name_instance)

        self.ui.progressBar.setValue(30)
        toConsole(self.ui, "Get structures from Server : ✔️")

        #### ENUMS CURRENT REGISTER
        all_enums = scripts_get_enums()
        ret = register_enums(self.ui, all_enums, self.ui.manager.name_instance)
        if ret:
            self.ui.progressBar.setValue(0)
            return -1
        
        self.ui.progressBar.setValue(35)
        toConsole(self.ui, "Register Enums to Server : ✔️")

        #### ENUMS SERVER GET 
        for instance in instances:
            enums = get_enums(self.ui, instance)
            if len(enums) > 0:
                self.ui.enums_all[instance] = enums
            
        if self.ui.manager.name_instance in self.ui.enums_all:    
            self.updateEnum(self.ui.enums_all[self.ui.manager.name_instance], self.ui.manager.name_instance)

        self.ui.progressBar.setValue(40)
        toConsole(self.ui, "Get enums from Server : ✔️")

        #### SYMBOLS CURRENT REGISTER
        
        all_symbols = scripts_get_symbols()
        ret = register_symbols(self.ui, all_symbols, self.ui.manager.name_instance)
        if ret:
            self.ui.progressBar.setValue(0)
            return -1
        
        self.ui.progressBar.setValue(45)
        toConsole(self.ui, "Register Symbols to Server : ✔️")

        #### SYMBOLS SERVER GET 
        
        for instance in instances:
            symbols = get_symbols(self.ui, instance)
            if len(symbols) > 0:
                self.ui.symbols_all[instance] = symbols
            
        if self.ui.manager.name_instance in self.ui.symbols_all:    
            self.updateSymbol(self.ui.symbols_all[self.ui.manager.name_instance], self.ui.manager.name_instance)

        self.ui.progressBar.setValue(50)
        toConsole(self.ui, "Get Symbols from Server : ✔️")
        
        
        ### ALL DONE
        self.ui.l_v_serv_status.setText("Connected")
        self.ui.progressBar.setValue(100)

    #Updates instances for qcombox of user selection
    def updateInstance(self, instances:dict) -> None:
        self.ui.instance_select.clear()

        if len(instances) == 0:
            self.ui.instance_select.addItem("No Instances found")
            return

        for instance in instances:
            self.ui.instance_select.addItem(instance)

        self.ui.instance_select.setCurrentText(self.ui.manager.name_instance)

    # This function is called to update QcomboBox of user selection of structure
    def updateStructures(self, structs:dict, instance:str):

        self.ui.structure_select.clear()
        self.ui.structs_all[instance] = structs

        for s_name in structs:
            self.ui.structure_select.addItem(s_name)
        
        struct_name_user_select = self.ui.structure_select.itemText(0)
        c_st = self.ui.structs_all[instance]
        for s_name in c_st:
            if s_name == struct_name_user_select:
                
                memb_aligned = c_st[s_name]['data']
                size = c_st[s_name]['size']
                
                self.ui.l_p_struc_size.setText("Size : ")
                self.ui.l_v_struc_size.setText(f"{size}")

                #format structure to human readable
                memb_aligned = memb_aligned.replace('{','\n{\n\t') 
                memb_aligned = memb_aligned.replace('};','}')
                memb_aligned = memb_aligned.replace(';',';\n\t')
                memb_aligned = memb_aligned.replace('\t}','}')

                self.ui.p_struc_overview.setText(f"{memb_aligned}")

    # This function is called to update QcomboBox of user selection of enums
    def updateEnum(self, enums:dict, instance:str) -> None:
        
        self.ui.enum_select.clear()
        self.ui.enums_all[instance] = enums

        for e_name in enums:
            self.ui.enum_select.addItem(e_name)
        
        enum_name_user_select = self.ui.enum_select.itemText(0)
        c_en = self.ui.enums_all[instance]
        for e_name in c_en:
            if e_name == enum_name_user_select:
                
                memb = c_en[e_name]['data']
                size = c_en[e_name]['size']
                
                self.ui.l_p_enum_size.setText("Size : ")
                self.ui.l_v_enum_size.setText(f"{size}")

                overview = "\n"

                for member in memb:
                    overview += f"--> Name={member} | Value = {memb[member]}\n"

                self.ui.p_enum_overview.setText(f"{overview}")

    # This function is called to update QcomboBox of user selection of enums
    def updateSymbol(self, symbol:dict, instance:str) -> None:
        
        self.ui.symbol_select.clear()
        self.ui.symbols_all[instance] = symbol

        for s_name in symbol:
            self.ui.symbol_select.addItem(s_name)

           

        symbol_name_user_select = self.ui.symbol_select.itemText(0)
        s_en = self.ui.symbols_all[instance]
        for s_name in s_en:
            if s_name == symbol_name_user_select:
                
                type = s_en[s_name]['signature']
                address = s_en[s_name]['address']

                overview = f"@{address}\n{type}"
                self.ui.p_symbol_sig.setText(f"{overview}")


    #main methods called when update , can be called manually or with a timer
    def update_(self, force_update:bool=False) -> None:

        if self.ui.is_server_connected == False:
            return
        
        if not hasChanged(self.ui) and not force_update:
            return
        
        pprint("Server has new data. Updating...")
        
        #update instance
        instances = get_instance(self.ui)
        if len(instances) == 0:
            return
        self.updateInstance(instances)
        self.ui.l_v_instance.setText(str(len(instances)))

        #update structures
        for instance in instances:
            structs = get_structure(self.ui, instance)
            if len(structs) > 0:
                self.ui.structs_all[instance] = structs

            enums = get_enums(self.ui, instance)
            if len(enums) > 0:
                self.ui.enums_all[instance] = enums

            symbols = get_symbols(self.ui, instance)
            if len(symbols) > 0:
                self.ui.symbols_all[instance] = symbols


        toConsole(self.ui, "Update from server : ✔️")


    #main methods to update structure field when user change struct in combo box
    def update_structure(self) -> None:

        cur_struct = self.ui.structure_select.currentText()

        if len(cur_struct) == 0 or cur_struct == "No Structures found":
            return

        cur_instance = self.ui.instance_select.currentText()
        if len(cur_instance) == 0 or cur_instance == "No Instances found":
            return
        
        if cur_instance not in self.ui.structs_all:
            self.ui.structure_select.clear()
            self.ui.structure_select.addItem("No Structures found")
            return
            
        structs = self.ui.structs_all[cur_instance]
        found = False

        for struct in structs:
            if struct == cur_struct:

                memb_aligned = structs[struct]['data']
                size = structs[struct]['size']
                
                self.ui.l_p_struc_size.setText("Size : ")
                self.ui.l_v_struc_size.setText(f"{size}")

                #format structure to human readable
                memb_aligned = memb_aligned.replace('{','\n{\n\t') 
                memb_aligned = memb_aligned.replace('};','}')
                memb_aligned = memb_aligned.replace(';',';\n\t')
                memb_aligned = memb_aligned.replace('\t}','}')

                self.ui.p_struc_overview.setText(f"{memb_aligned}")
                found=True

        if not found:
            print(f"[IdaSync] {cur_struct} not found in memory. Probably a bug. Skipping Update")
            return

    #main methods to update all data when user change instance in combo box
    def update_property(self) -> None:
        
        cur_instance = self.ui.instance_select.currentText()
        if len(cur_instance) == 0 or cur_instance == "No Instances found":
            return
        
        #update structure page
        if cur_instance in self.ui.structs_all:
            structs = self.ui.structs_all[cur_instance]
            self.updateStructures(structs, cur_instance)
        else:
            self.ui.structure_select.clear()
            self.ui.structure_select.addItem("No Structures found")

        #update enums page
        if cur_instance in self.ui.enums_all:
            enums = self.ui.enums_all[cur_instance]
            self.updateEnum(enums, cur_instance)
        else:
            self.ui.enum_select.clear()
            self.ui.enum_select.addItem("No Enums found")

        #update symbol page
        if cur_instance in self.ui.symbols_all:
            symbol = self.ui.symbols_all[cur_instance]
            self.updateSymbol(symbol, cur_instance)
        else:
            self.ui.symbol_select.clear()
            self.ui.symbol_select.addItem("No Symbols found")

    #main methods to import selected structure from user selection
    def import_struct(self) -> None:

        cur_struct = self.ui.structure_select.currentText()

        if len(cur_struct) == 0 or cur_struct == "No Structures found":
            return
        
        cur_instance = self.ui.instance_select.currentText()
        if len(cur_instance) == 0 or cur_instance == "No Instances found":
            return
        
        toConsole(self.ui, f"Importing structure : {cur_struct}")

        s_ins = self.ui.structs_all.get(cur_instance)
        if not s_ins:
            toConsole(self.ui, f"No structures found in internal for {cur_instance}")
            return

        s_data = s_ins.get(cur_struct)
        if not s_data:
            toConsole(self.ui, f"Structure : {cur_struct} not found in {cur_instance} structures")
            return
        
        s_data_raw = s_data['data']
        script_import_structure(cur_struct, s_data_raw)

    #main methods to import selected enum from user selection
    def import_enum(self) -> None:

        cur_enum = self.ui.enum_select.currentText()

        if len(cur_enum) == 0 or cur_enum == "No Enums found":
            return
        
        cur_instance = self.ui.instance_select.currentText()
        if len(cur_instance) == 0 or cur_instance == "No Instances found":
            return
        
        toConsole(self.ui, f"Importing enum : {cur_enum}")

        s_ins = self.ui.enums_all.get(cur_instance)
        if not s_ins:
            toConsole(self.ui, f"No Enums found in internal for {cur_instance}")
            return

        s_data = s_ins.get(cur_enum)
        if not s_data:
            toConsole(self.ui, f"Enum : {cur_enum} not found in {cur_instance} enums")
            return
        
        s_data_raw = s_data['data']
        scripts_import_enum(cur_enum, s_data_raw)

    #main methods to import selected symbol from user selection
    def import_symbol(self) -> None:

        cur_symbol = self.ui.symbol_select.currentText()

        if len(cur_symbol) == 0 or cur_symbol == "No Symbols found":
            return
        
        cur_instance = self.ui.instance_select.currentText()
        if len(cur_instance) == 0 or cur_instance == "No Instances found":
            return
        
        toConsole(self.ui, f"Importing symbol : {cur_symbol}")

        s_ins = self.ui.symbols_all.get(cur_instance)
        if not s_ins:
            toConsole(self.ui, f"No Symbol found in internal for {cur_instance}")
            return

        s_data = s_ins.get(cur_symbol)
        if not s_data:
            toConsole(self.ui, f"Symbol : {cur_symbol} not found in {cur_instance} symbols")
            return
        
        ret = scripts_import_symbol(s_data, cur_symbol)
        if not ret:
            return
        
        if ret == 3:
            toConsole(self.ui, f"Failed to set type for symbol : {cur_symbol}")
        else:
            toConsole(self.ui, f"Failed to import symbol : {cur_symbol}")

    #main method to update enum tab from user selection
    def update_enum(self) -> None:
        cur_enum = self.ui.enum_select.currentText()

        if len(cur_enum) == 0 or cur_enum == "No Enums found":
            return

        cur_instance = self.ui.instance_select.currentText()
        if len(cur_instance) == 0 or cur_instance == "No Instances found":
            return
        
        if cur_instance not in self.ui.enums_all:
            self.ui.enum_select.clear()
            self.ui.enum_select.addItem("No Enums found")
            return
            
        enums = self.ui.enums_all[cur_instance]
        found = False

        for enum in enums:
            if enum == cur_enum:

                memb = enums[enum]['data']
                size = enums[enum]['size']
                
                self.ui.l_p_enum_size.setText("Size : ")
                self.ui.l_v_enum_size.setText(f"{size}")
                
                overview = "\n"
                for member in memb:
                    overview += f"--> Name={member} | Value = {memb[member]}\n"

                self.ui.p_enum_overview.setText(f"{overview}")
                found=True

        if not found:
            print(f"[IdaSync] {cur_enum} not found in memory. Probably a bug.")

    #main method to update symbol tab from user selection
    def update_symbol(self) -> None:
        cur_symbol = self.ui.symbol_select.currentText()

        if len(cur_symbol) == 0 or cur_symbol == "No Symbols found":
            return

        cur_instance = self.ui.instance_select.currentText()
        if len(cur_instance) == 0 or cur_instance == "No Instances found":
            return
        
        if cur_instance not in self.ui.symbols_all:
            self.ui.symbol_select.clear()
            self.ui.symbol_select.addItem("No Symbols found")
            return
            
        symbols = self.ui.symbols_all[cur_instance]
        found = False

        for symb in symbols:
            if symb == cur_symbol:

                type = symbols[symb]['signature']
                address = symbols[symb]['address']

                overview = f"@{address}\n{type}"
                self.ui.p_symbol_sig.setText(f"{overview}")
                found=True

        if not found:
            print(f"[IdaSync] {cur_symbol} not found in memory. Probably a bug.")

    #main methods to update config.json with user settings
    def update_config(self) -> None:
        if os.name == "posix":
            cache_dir = os.path.expandvars("/$HOME/.idasync/")
        elif os.name == "nt":
            cache_dir = os.path.expandvars("%APPDATA%/IDASync/")
        else:
            return
        
        config = os.path.join(cache_dir, "config.json")
        if not os.path.exists(config):
            pprint("[Error] Config file not found: %s" % config)
            return
        
        currentIP = self.ui.le_v_ip.toPlainText()
        currentPort = self.ui.le_v_port.toPlainText()
        currentTiming = self.ui.l_v_sync_time.toPlainText()

        currentPortCasted = None
        try:
            currentPortCasted = int(currentPort)
        except Exception as e:
            pprint("[Error] couldn't cast port to int -> {} -> {}".format(currentPort, e))
            return
        
        currentTimingCasted = None
        try:
            currentTimingCasted = int(currentTiming)
        except Exception as e:
            pprint("[Error] couldn't cast timing to int -> {} -> {}".format(currentTiming, e))
            return

        with open(config, 'r') as file:
            data = json.load(file)
            file.close()

        data['ip'] = currentIP
        data['port'] = currentPortCasted
        data['update_time'] = currentTimingCasted

        data_ = json.dumps(data, indent=4)

        with open(config, 'w') as file:
            file.write(data_)
            file.close()

        pprint("Sucessfully dumped user settings to config : {} | Reload Plugin to apply new config".format(config))

        self.ui.ip = data['ip']
        self.ui.port = data['port']
