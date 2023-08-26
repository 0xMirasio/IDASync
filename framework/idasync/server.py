from xmlrpc.server import SimpleXMLRPCServer
import sys

def helloworld():
    return "Hello, World!"

def main():

    args = len(sys.argv)
    if (args < 2):
        print("Usage : python3 -m idasync runserver")
        sys.exit(0)

    if sys.argv[1] == "runserver":

        with SimpleXMLRPCServer(('localhost', 4444)) as server:
            server.register_function(helloworld, 'helloworld')
            print("Serving on port 4444...")
            server.serve_forever()
    else:
        print("Unknow command")

if __name__ == "__main__":
    main()