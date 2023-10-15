# IDASync

Automatic IDA instance syncing for better reverse.

### Features
* Connect multi IDA instance to a local server to sync Enum, Structure, Symbol
* Sync Signature information (function header)
* Allow multiple users to work on differents instances and sync data. 


### Installation
```
$ python install.py
```

**Manual installation**: 
 * copy the [plugin/idasync](plugin/idasync/) directory and [plugin/idasync.py](plugin/idasync.py) into IDA plugins folder.
 * cd framework && pip install .


### Usage

Server must be run before using the plugin : **python3 -m idasyncserver** or **idasyncserver**
You can install it on a custom server, then modify config.json to connect to it with others users.

Use **CTRL+Shift+F3** in IDA to connect to server.
* see [config.json](config.json) - configuration to be used
    * config.json can be updated in parameters tab in plugins GUI
        - IP : ip to connect
        - Port : port to connect
        - Update Timing : Time between sync with server. If you have issues with syncing with server (lag, freeze etc), rise the update timing value to fix the problem (can happen with laggy server)


For tutorial/exemple, see [ressource/example.md](ressource/example.md)

## TODO : 

see [PLAN.md](PLAN.md)

## Support

Tested on : 
* Windows x64

**Tested on IDA Pro 7.7 but should work with any IDA Pro 7.X+**
**Tested on Python 3.10 but should work with any Python 3.X+**

## Disclaimer
IDASync is still in development and might not fit every use cases.
This project is the v2 of IDAAutoResolv , reworked and largly extended.

