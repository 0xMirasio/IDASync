from idasync.idascripts.struct import scripts_get_structures,script_import_structure
from idasync.api_wrapper import get_instance,ping,register_instance,register_structure,get_structure,hasChanged
from idasync.util import toConsole,pprint
from idasync.apiclient import Client

import os
import json

#Updates instances for qcombox of user selection
def updateInstance(self, instances):
    self.instance_select.clear()

    if len(instances) == 0:
        self.instance_select.addItem("No instance found")
        return

    for instance in instances:
        self.instance_select.addItem(instance)

    self.instance_select.setCurrentText(self.manager.name_instance)


# This function is called to update QcomboBox of user selection of structure
def updateStructures(self, structs, instance):

    self.structure_select.clear()
    self.structs_all[instance] = structs

    for s_name in structs:
        self.structure_select.addItem(s_name)
    
    struct_name_user_select = self.structure_select.itemText(0)
    c_st = self.structs_all[instance]
    for s_name in c_st:
        if s_name == struct_name_user_select:
            
            memb_aligned = c_st[s_name]['data']
            size = c_st[s_name]['size']
            
            self.l_p_struc_size.setText("Size : ")
            self.l_v_struc_size.setText(f"{size}")

            #format structure to human readable
            memb_aligned = memb_aligned.replace('{','\n{\n\t') 
            memb_aligned = memb_aligned.replace('};','}')
            memb_aligned = memb_aligned.replace(';',';\n\t')
            memb_aligned = memb_aligned.replace('\t}','}')

            self.p_struc_overview.setText(f"{memb_aligned}")

    return 0

# main method called when user connect to server
def connectRPC(self):

    self.progressBar.setValue(10)

    ret = ping(self)
    if ret:
        self.progressBar.setValue(0)     
        return -1
    
    self.progressBar.setValue(20)
    toConsole(self, "Ping Server : Sucess")

    ret = register_instance(self, self.manager.name_instance)
    if ret:
        self.progressBar.setValue(0)
        return -1
    
    self.is_server_connected = True
    
    self.progressBar.setValue(30)
    toConsole(self, "Register Instances to Server : Sucess")
    
    instances = get_instance(self)
    if len(instances) == 0:
        self.progressBar.setValue(0)
        return -1
    
    self.progressBar.setValue(40)
    toConsole(self, "Get Instances from Server : Sucess")
    
    updateInstance(self, instances)
    self.l_v_instance.setText(str(len(instances)))

    all_structures = scripts_get_structures()
    ret = register_structure(self, all_structures, self.manager.name_instance)
    if ret:
        self.progressBar.setValue(0)
        return -1
    
    self.progressBar.setValue(50)
    toConsole(self, "Register structures to Server : Sucess")

    for instance in instances:
        structs = get_structure(self, instance)
        if len(structs) > 0:
            self.structs_all[instance] = structs
        
    if self.manager.name_instance in self.structs_all:    
        updateStructures(self, self.structs_all[self.manager.name_instance], self.manager.name_instance)

    self.progressBar.setValue(60)
    toConsole(self, "Get structures from Server : Sucess")
    
    self.l_v_serv_status.setText("Connected")
    self.progressBar.setValue(100)

#main methods called when update , can be called manually or with a timer
def update_(self):

    if self.is_server_connected == False:
        return
    
    if not hasChanged(self):
        return
    
    pprint("Server has new data. Updating...")
    
    #update instance
    instances = get_instance(self)
    if len(instances) == 0:
        return
    updateInstance(self, instances)
    self.l_v_instance.setText(str(len(instances)))

    #update structures
    for instance in instances:
        structs = get_structure(self, instance)
        if len(structs) > 0:
            self.structs_all[instance] = structs


    toConsole(self, "Update from server : Sucess")


#main methods to update structure field when user change struct in combo box
def update_structure(self):

    cur_struct = self.structure_select.currentText()

    if len(cur_struct) == 0 or cur_struct == "No structure found":
        return

    cur_instance = self.instance_select.currentText()
    if len(cur_instance) == 0 or cur_instance == "No instance found":
        return
        
    structs = self.structs_all[cur_instance]
    found = False

    for struct in structs:
        if struct == cur_struct:

            memb_aligned = structs[struct]['data']
            size = structs[struct]['size']
            
            self.l_p_struc_size.setText("Size : ")
            self.l_v_struc_size.setText(f"{size}")

            #format structure to human readable
            memb_aligned = memb_aligned.replace('{','\n{\n\t') 
            memb_aligned = memb_aligned.replace('};','}')
            memb_aligned = memb_aligned.replace(';',';\n\t')
            memb_aligned = memb_aligned.replace('\t}','}')



            self.p_struc_overview.setText(f"{memb_aligned}")

            found=True

    if not found:
        print(f"[IdaSync] {cur_struct} not found in memory. Probably a bug. Skipping Update")
        return

#main methods to update all data when user change instance in combo box
def update_property(self):
    

    cur_instance = self.instance_select.currentText()
    if len(cur_instance) == 0 or cur_instance == "No instance found":
        return
    
    #update structure page
    if cur_instance in self.structs_all:
        structs = self.structs_all[cur_instance]
        updateStructures(self, structs, cur_instance)

#main methods to import selected structure from user selection
def import_struct(self):

    cur_struct = self.structure_select.currentText()

    if len(cur_struct) == 0 or cur_struct == "No structure found":
        return
    
    cur_instance = self.instance_select.currentText()
    if len(cur_instance) == 0 or cur_instance == "No instance found":
        return
    
    toConsole(self, f"Importing structure : {cur_struct}")

    s_ins = self.structs_all.get(cur_instance)
    if not s_ins:
        toConsole(self, f"No structures found in internal for {cur_instance}")
        return

    s_data = s_ins.get(cur_struct)
    if not s_data:
        toConsole(self, f"Structure : {cur_struct} not found in {cur_instance} structures")
        return
    
    s_data_raw = s_data['data']
    script_import_structure(cur_struct, s_data_raw)


#main methods to update config.json with user settings
def update_config(self):
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
    
    currentIP = self.le_v_ip.toPlainText()
    currentPort = self.le_v_port.toPlainText()
    currentTiming = self.l_v_sync_time.toPlainText()

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

    self.ip = data['ip']
    self.port = data['port']
