from idasync.util import toConsole

#return instances from idasyncsserver
def get_instance(self):
    (ret, err, instances) = self.client.get_instance()
    if ret:
        toConsole(self, f"Couldn't get connected instances of Server : {err}")
        return []
    
    return instances

#ping idasyncsserver
def ping(self):
    (ret, err) = self.client.ping()
    if ret:
        toConsole(self, f"Couldn't connect to Server : {err}")
        toConsole(self, "You can run server with : \npython3 -m idasync runserver") 
        return -1
    
    return 0
    
#return instance to idasyncsserver
def register_instance(self, instance):
    (ret, err) = self.client.register_instance(instance)
    if ret:
        toConsole(self, f"Couldn't register instance to Server : {err}")
        return -1
    
    return 0

#registers structures to idasyncsserver
def register_structure(self, structure, instance):
    (ret, err) = self.client.register_structs(structure, instance)
    if ret:
        toConsole(f"Couldn't register structs to Server : {err}")
        return -1
    
#return structures from idasyncsserver    
def get_structure(self, instance):
    (ret, err, structs) = self.client.get_structs(instance)
    if ret:
        toConsole(f"Couldn't gets structs from Server : {err}")
        return {}
    
    return structs

#return boolean value if server has new value in memory
def hasChanged(self):
    (ret, err, update) = self.client.server_hasNewUpdate()
    if ret:
        toConsole(f"Couldn't gets hasChanged response from Server : {err}")
        return {}
       
    return update