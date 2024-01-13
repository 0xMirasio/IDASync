from idasync.util import toConsole

#return instances from idasyncsserver
def get_instance(self) -> dict:
    (ret, err, instances) = self.client.get_instance()
    if ret:
        toConsole(self, f"Couldn't get connected instances of Server : {err}")
        return []
    
    return instances

#ping idasyncsserver
def ping(self) -> int:
    (ret, err) = self.client.ping()
    if ret:
        toConsole(self, f"Couldn't connect to Server : {err}")
        toConsole(self, "You can run server with : \npython3 -m idasyncserver runserver") 
        return -1
    
    return 0
    
#return instance to idasyncsserver
def register_instance(self, instance:str)->int:
    (ret, err) = self.client.register_instance(instance)
    if ret:
        toConsole(self, f"Couldn't register instance to Server : {err}")
        return -1
    
    return 0

#registers structures to idasyncsserver
def register_structure(self, structure:dict, instance:str)->int:
    (ret, err) = self.client.register_structs(structure, instance)
    if ret:
        toConsole(self, f"Couldn't register structs to Server : {err}")
        return -1
    return 0
    
#registers enums to idasyncsserver
def register_enums(self, enums:dict, instance:str)->int:
    (ret, err) = self.client.register_enums(enums, instance)
    if ret:
        toConsole(self, f"Couldn't register enums to Server : {err}")
        return -1
    return 0

#registers symbols to idasyncsserver
def register_symbols(self, symbols:dict, instance:str)->int:
    (ret, err) = self.client.register_symbols(symbols, instance)
    if ret:
        toConsole(self, f"Couldn't register symbols to Server : {err}")
        return -1
    return 0
    
#return structures from idasyncsserver    
def get_structure(self, instance:str)->dict:
    (ret, err, structs) = self.client.get_structs(instance)
    if ret:
        toConsole(f"Couldn't gets structs from Server : {err}")
        return {}
    
    return structs

#return enums from idasyncsserver    
def get_enums(self, instance:str)->dict:
    (ret, err, enums) = self.client.get_enums(instance)
    if ret:
        toConsole(f"Couldn't gets enums from Server : {err}")
        return {}
    
    return enums

#return symbols from idasyncsserver    
def get_symbols(self, instance:str)->dict:
    (ret, err, symbols) = self.client.get_symbols(instance)
    if ret:
        toConsole(f"Couldn't gets symbols from Server : {err}")
        return {}
    
    return symbols

#return boolean value if server has new value in memory
def hasChanged(self)->bool:
    instance = self.manager.name_instance
    (ret, err, update) = self.client.server_hasNewUpdate(instance)
    if ret:
        toConsole(self, f"Couldn't gets hasChanged response from Server : {err}")
        return {}
       
    return update