import httpx

class Client():
    def __init__(self) -> None:
        self.base_url = "http://localhost:4444"
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
                if len(result) == 0:
                    return (1, "[ERROR] get_instance() returned no instance", "")
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
            response = self.client.post(f"{self.base_url}/register_instance/", json={"instance": instance})
            if response.status_code == 200 and response.text == "disconnect_instance_ok":
                return (0, "")
            return (1, "[ERROR] disconnect_instance() failed")
            
        except Exception as e:
            return (1, str(e))

def main():
    cli = Client()

    (r,err) = cli.ping()
    if r:
        print(err)
        return -1
    
    print("ok ping")

    (ret, err) = cli.register_instance("test_client")
    if ret:
        print(f"Couldn't register instance to Server : {err}")
        return -1
    
    print("ok register_instance")

    (ret, err, instances) = cli.get_instance()
    if ret:
        print(f"Couldn't get instances from Server : {err}")
        return -1
    
    print(instances)



if __name__ == "__main__":
    main()