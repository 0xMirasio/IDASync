from fastapi import FastAPI
from typing import List, Optional

app = FastAPI()

from pydantic import BaseModel

class Instance(BaseModel):
    instance: str

class Server():
    def __init__(self):
        self.instances = []

    def ping(self):
        return "ping_ok"
    
    def register_instance(self, instance: str):
        if instance in self.instances:
            return "register_instance_ok"
        
        self.instances.append(instance)
        return "register_instance_ok"
    
    def disconnect_instance(self, instance: str):
        if instance not in self.instances:
            return "instance_not_found"
        
        self.instances.remove(instance)
        return "disconnect_instance_ok"

    def get_instance(self):
        return self.instances

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

@app.get("/get_instance/")
def get_instance():
    return server_instance.get_instance()

def main():
    import uvicorn
    uvicorn.run(app, host="localhost", port=4444)

if __name__ == "__main__":
    main()