from idasync.idascripts.getstruct import scripts_get_structures
import json

def update_console(self):
    tt_console = ""
    for item in self.console_:
        tt_console += item + "\n"

    self.p_console.setText(tt_console)


def toConsole(self, msg):
    self.console_.append(msg)
    update_console(self)


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
        toConsole(self, f"Couldn't get connected instances of Server : {err}")
        return []
    
    return instances

def ping(self):
    (ret, err) = self.client.ping()
    if ret:
        toConsole(self, f"Couldn't connect to Server : {err}")
        toConsole(self, "You can run server with : \npython3 -m idasync runserver") 
        return -1
    
    return 0
    
def register_instance(self, instance):
    (ret, err) = self.client.register_instance(instance)
    if ret:
        toConsole(self, f"Couldn't register instance to Server : {err}")
        return -1
    
    return 0

def register_structure(self, structure, instance):
    (ret, err) = self.client.register_structs(structure, instance)
    if ret:
        toConsole(f"Couldn't register structs to Server : {err}")
        return -1
    
def get_structure(self, instance):
    (ret, err, structs) = self.client.get_structs(instance)
    if ret:
        toConsole(f"Couldn't gets structs from Server : {err}")
        return {}
    
    return structs

def updateStructures(self, structs, instance):

    self.structure_select.clear()
    self.structs[instance] = structs
    for item in structs:
        s_name = item["struct_name"]
        
        self.structure_select.addItem(s_name)

    
    fi = self.structure_select.itemText(0)
    c_st = self.structs[instance]
    for st in c_st:
        if st["struct_name"] == fi:
            s_size = st["size"]
            s_members = st["members"]

            self.l_p_struc_size.setText("Size : ")
            self.l_v_struc_size.setText(f"{s_size}")

            memb_aligned = json.dumps(s_members, indent=4)
            self.p_struc_overview.setText(f"{memb_aligned}")

    return 0

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

    structs_ = get_structure(self, self.manager.name_instance)
    if len(structs_) > 0:
        updateStructures(self, structs_, self.manager.name_instance)

    self.progressBar.setValue(60)
    toConsole(self, "Get structures from Server : Sucess")
    
    self.l_v_serv_status.setText("Connected")
    self.progressBar.setValue(100)
    self.is_server_connected = True

def update_(self):
    if self.is_server_connected == False:
        return
    
    instances = get_instance(self)
    if len(instances) == 0:
        return -1
    
    updateInstance(self, instances)
    self.l_v_instance.setText(str(len(instances)))

