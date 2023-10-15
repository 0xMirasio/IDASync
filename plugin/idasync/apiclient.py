import httpx

from idasync.util import pprint

class Client():
    def __init__(self, ip, port) -> None:
        self.base_url = f"http://{ip}:{port}"
        self.client = httpx.Client()
        

    def ping(self):
        try:
            response = self.client.get(f"{self.base_url}/ping")
            if response.status_code == 200 and response.text.replace('"','') == "ping_ok":
                return (0, "")
            return (1, "[ERROR] ping returned unknown response")
            
        except Exception as e:
            return (1, str(e))
        

    def get_instance(self):
        try:
            response = self.client.get(f"{self.base_url}/get_instance/")
            if response.status_code == 200:
                result = response.json()
                return (0, "", result)
            return (1, f"[ERROR] Status code: {response.status_code}", "")
            
        except Exception as e:
            return (1, str(e), "")
           

    def register_instance(self, instance):
        try:
            response = self.client.post(f"{self.base_url}/register_instance/", json={"instance": instance})
            if response.status_code == 200 and response.text.replace('"','') == "register_instance_ok":
                return (0, "")
            return (1, f"[ERROR] register_instance() failed : {response.text}")
            
        except Exception as e:
            return (1, str(e))
        
    def disconnect_instance(self, instance):
        try:
            response = self.client.post(f"{self.base_url}/disconnect_instance/", json={"instance": instance})
            if response.status_code == 200 and response.text.replace('"','') == "disconnect_instance_ok":
                return (0, "")
            return (1, "[ERROR] disconnect_instance() failed")
            
        except Exception as e:
            return (1, str(e))
        
    def register_structs(self, structs, instance):

        try:

            package = {
                "data" : {
                    "structs" : structs,
                    "instance" : instance
                }
            }
            response = self.client.post(f"{self.base_url}/register_structs/", json=package)
            if response.status_code == 200 and response.text.replace('"','') == "register_structs_ok":
                return (0, "")
            return (1, f"[ERROR] register_structs() failed : {response.text}")
            
        except Exception as e:
            return (1, str(e))
        
    def get_structs(self, instance):
        try:
            response = self.client.post(f"{self.base_url}/get_structs/", json={"instance": instance})
            if response.status_code == 200:
                result = response.json()
                return (0, "", result)
            
            return (1, f"[ERROR] get_structs() failed : {response.text}", {})
            
        except Exception as e:
            return (1, str(e), {})
        
    def server_hasNewUpdate(self):
        try:
            response = self.client.get(f"{self.base_url}/hasNewUpdate/")
            if response.status_code == 200:
                if response.text.replace('"','') == "serverHasNewUpdate":
                    return (0, "", 1)
            
                elif response.text.replace('"','') == "serverHasNoNewUpdate":
                    return (0, "", 0)
                else:
                    return (1, "[ERROR] Unknow response msg from server", 0)
            
            return (1, f"[ERROR] hasNewUpdate() failed : {response.text}", {})
            
        except Exception as e:
            return (1, str(e), 0)