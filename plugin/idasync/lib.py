from idasync.idascripts.getstruct import scripts_get_structures
import json
from idasync.api_wrapper import get_instance,ping,register_instance,register_structure,get_structure,hasChanged
from idasync.util import toConsole,pprint

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
    for item in structs:
        s_name = item["struct_name"]
        self.structure_select.addItem(s_name)
    
    fi = self.structure_select.itemText(0)
    c_st = self.structs_all[instance]
    for st in c_st:
        if st["struct_name"] == fi:
            s_size = st["size"]
            s_members = st["members"]

            self.l_p_struc_size.setText("Size : ")
            self.l_v_struc_size.setText(f"{s_size}")

            memb_aligned = json.dumps(s_members, indent=4)
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

    struct_ = scripts_get_structures()
    ret = register_structure(self, struct_, self.manager.name_instance)
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
    self.is_server_connected = True

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

    for st in structs:
        if st["struct_name"] == cur_struct:

            s_size = st["size"]
            s_members = st["members"]

            self.l_v_struc_size.setText(f"{s_size}")

            memb_aligned = json.dumps(s_members, indent=4)
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

