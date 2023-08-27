from fastapi import FastAPI
from typing import List, Optional

app = FastAPI()

from pydantic import BaseModel

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

    def ping(self):
        return "ping_ok"
    
    def register_instance(self, instance: str):
        if instance in self.instances:
            return "register_instance_ok"
        
        self.instances.append(instance)
        return "register_instance_ok"
    
    def disconnect_instance(self, instance: str):
        if instance not in self.instances:
            return "disconnect_instance_ok"
        
        self.instances.remove(instance)
        return "disconnect_instance_ok"

    def get_instance(self):
        return self.instances
    
    def register_structs(self, structs, instance):
        if instance not in self.instances:
            return "instance_not_found"
        
        self.structs_[instance] = structs
        return "register_structs_ok"
    
    def get_structs(self, instance):
        if instance not in self.structs_:
            return "instance_not_found"
        
        return self.structs_[instance]

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

def main():
    import uvicorn
    uvicorn.run(app, host="localhost", port=4444)

if __name__ == "__main__":
    main()