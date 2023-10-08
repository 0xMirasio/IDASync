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
    
    print("Get instance from server : ", instances)


    test_struct = {
        'TestStructTestClient' : {
                "data": "struct test  __attribute__((aligned(8))) {unsigned __int32 st_name;unsigned __int8 st_info;unsigned __int8 st_other;unsigned __int16 st_shndx;unsigned __int64 st_value;unsigned __int64 st_size;};",
                "size": 6,
        }
    }
                

    (ret, err) = cli.register_structs(test_struct, "test_client")
    if ret:
        print(f"Couldn't register structs to Server : {err}")
        return -1

    print("register structs ok")

    (ret, err, structs) = cli.get_structs("test_client")
    if ret:
        print(f"Couldn't gets structs from Server : {err}")
        return -1

    print("gets structs of test_client from server : ", structs) 


    (ret, err) = cli.disconnect_instance("test_client")
    if ret:
        print(f"Couldn't remove instance from Server : {err}")
        return -1

    print("disconnect instance ok")




if __name__ == "__main__":
    main()