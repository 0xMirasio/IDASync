from fastapi import FastAPI
from typing import List, Optional

app = FastAPI()
import os
from pydantic import BaseModel
import json

DEBUG = True

class Instance(BaseModel):
    instance: str

class Structs(BaseModel):
    structs: dict

class Package(BaseModel):
    data: dict


def getConfig():
    if os.name == "posix":
        cache_dir = os.path.expandvars("/$HOME/.idasync/")
    elif os.name == "nt":
        cache_dir = os.path.expandvars("%APPDATA%/IDASync/")
    else:
        raise Exception("Unknow/Unsupported OS : %s" % os.name)
    
    config = os.path.join(cache_dir, "config.json")
    if not os.path.exists(config):
        raise Exception("Config file not found: %s" % config)
    
    print("Found config file: %s" % config)
    
    with open(config, 'r') as file:
        data = json.load(file)

    port = data["port"]
    ip = data["ip"]

    return ip,port
        
    


class Server():
    def __init__(self):
        self.instances = []
        self.structs_ = {}

        self.ServerNewData = False

    def debugCurrentServerInformation(self):
        print("[Debug] Server information")
        print(f"[Debug] instance -> {self.instances}")
        print(f"[Debug] Structures -> {self.structs_}")
        print(f"[Debug] ServerNewData -> {self.ServerNewData}")

    def ping(self):
        return "ping_ok"
    
    def register_instance(self, instance: str):
        if instance in self.instances:
            return "register_instance_ok"
        
        self.instances.append(instance)
        self.ServerNewData = True
        
        return "register_instance_ok"
    
    def disconnect_instance(self, instance: str):
        if instance not in self.instances:
            return "disconnect_instance_ok"
        
        self.instances.remove(instance)
        self.structs_.pop(instance, None)
        self.ServerNewData = True

        if DEBUG:
            self.debugCurrentServerInformation()
        return "disconnect_instance_ok"

    def get_instance(self):
        return self.instances
    
    def register_structs(self, structs, instance):
        if instance not in self.instances:
            return "instance_not_found"
        
        self.structs_[instance] = structs
        self.ServerNewData = True

        return "register_structs_ok"
    
    def get_structs(self, instance):
        if instance not in self.structs_:
            return "instance_not_found"
        
        return self.structs_[instance]
    
    def hasNewUpdate(self):

        if DEBUG:
            self.debugCurrentServerInformation()
            
        if self.ServerNewData:
            self.ServerNewData = False
            return "serverHasNewUpdate"
        else:
            return "serverHasNoNewUpdate"
        

server_instance = Server()

@app.get("/ping")
def ping():
    return server_instance.ping()

@app.post("/register_instance/")
def register_instance(instance: Instance):
    return server_instance.register_instance(instance.instance)

@app.post("/disconnect_instance/")
def disconnect_instance(instance: Instance):
    return server_instance.disconnect_instance(instance.instance)

@app.post("/register_structs/")
def register_structs(package: Package):
    return server_instance.register_structs(package.data["structs"],package.data["instance"])

@app.post("/get_structs/")
def get_structs(instance: Instance):
    return server_instance.get_structs(instance.instance)

@app.get("/get_instance/")
def get_instance():
    return server_instance.get_instance()

@app.get("/hasNewUpdate/")
def get_hasNewUpdate():
    return server_instance.hasNewUpdate()

def main():
    import uvicorn
    host_, port_ = getConfig()

    print(f"[IDASyncServer] Running on port {host_}:{port_}")
    uvicorn.run(app, host=host_, port=port_)

if __name__ == "__main__":
    main()