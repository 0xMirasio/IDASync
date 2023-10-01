import datetime

def update_console(self):
    tt_console = ""
    for item in self.console_:
        tt_console += item + "\n"

    self.p_console.setText(tt_console)


def toConsole(self, msg):
    self.console_.append(msg)
    update_console(self)


def pprint(msg):

    dt = datetime.datetime.now()
    print(f"[{dt}] - [IDASync] --> {msg}")
