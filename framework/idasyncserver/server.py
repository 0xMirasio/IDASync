from fastapi import FastAPI
from typing import List, Optional

app = FastAPI()

from pydantic import BaseModel

PORT = 4444
HOST= "127.0.0.1"
DEBUG = True

class Instance(BaseModel):
    instance: str

class Structs(BaseModel):
    structs: dict

class Package(BaseModel):
    data: dict

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
    print(f"[IDASyncServer] Running on port {HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT)

if __name__ == "__main__":
    main()