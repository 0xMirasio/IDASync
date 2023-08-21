# IDASync

Automatic IDA instance syncing for better reverse.

### Features
* Connect multi IDA instance to a local server to sync Enumn, Structure, Symbol
* Sync Signature information (fonction header)
* Sync Code
* Allow multiple users to work on differents instances and sync data. 


### Installation
```
$ python plugin/install.py
```

**Manual installation**: copy the [plugin/idasync](plugin/idasync/) directory and [plugin/idasync.py](plugin/idasync.py) into IDA plugins folder.


### Usage

Use CTRL+Shift+F3 in IDA to connect to server. (or any hotkey you want, see CONFIG.py)
* see ```plugin/config.json``` - configuration to be used, you can change settings before installing framework

For functionality, see ressource/paper.pdf

## TODO : 

* test linux support
* create test_binaries/ with multiple architectures for testing

## Support

Tested on : 
* Windows x64

**Tested on IDA Pro 7.7 but should work with any IDA Pro 7.X+**
**Tested on Python 3.10 but should work with any Python 3.X+**

## Disclaimer
IDASync is still in development and might not fit every use cases.
This project is the v2 of IDAAutoResolv , reworked and largly extended.

