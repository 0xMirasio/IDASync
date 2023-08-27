import httpx

from idasync.logging import pprint

class Client():
    def __init__(self) -> None:
        self.base_url = "http://localhost:4444"
        self.client = httpx.Client()
        

    def ping(self):
        try:
            response = self.client.get(f"{self.base_url}/ping")
            print(response.status_code, response.text, response.status_code == 200, response.text == "ping_ok" )
            if response.status_code == 200 and response.text == "ping_ok":
                return (0, "")
            return (1, "[ERROR] ping returned unknown response")
            
        except Exception as e:
            return (1, str(e))
        

    def get_instance(self):
        try:
            response = self.client.get(f"{self.base_url}/get_instance/")
            if response.status_code == 200:
                result = response.json()
                if len(result) == 0:
                    return (1, "[ERROR] get_instance() returned no instance", "")
                return (0, "", result)
            return (1, f"[ERROR] Status code: {response.status_code}", "")
            
        except Exception as e:
            return (1, str(e), "")
           

    def register_instance(self, instance):
        try:
            response = self.client.post(f"{self.base_url}/register_instance/", data={"instance": instance})
            if response.status_code == 200 and response.text == "register_instance_ok":
                return (0, "")
            return (1, "[ERROR] register_instance() failed")
            
        except Exception as e:
            return (1, str(e))
        
    def disconnect_instance(self, instance):
        try:
            response = self.client.delete(f"{self.base_url}/disconnect_instance/", data={"instance": instance})
            if response.status_code == 200 and response.text == "disconnect_instance_ok":
                return (0, "")
            return (1, "[ERROR] disconnect_instance() failed")
            
        except Exception as e:
            return (1, str(e))
