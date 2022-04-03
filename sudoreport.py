#!/usr/bin/env python3
import pathlib
import re

class SudoEvent:
    def __init__(self, match) -> None:
        self.month = match.group('month')
        self.day = match.group('day')
        self.timestamp = match.group('timestamp')
        self.hostname = match.group('hostname')
        self.process = match.group('process')
        self.pid = match.group('pid')
        self.user = match.group('user')
        self.tty = match.group('tty')
        self.pwd = match.group('pwd')
        self.sudo_user = match.group('sudo_user')
        self.command = match.group('command')
        self.args = match.group('args')

    def sudo_print(self):
        print('Sudo activity for user: ' + self.user + ' at ' + self.month + ' ' + self.day + ' ' + self.timestamp)
        print('Command used: ' + self.command)
        print('Flags: ' + self.args, end='\n\n')


def summary_update(recap, event):
    if event.user not in recap:
        recap[event.user] = {'cmd_nb': 1}
    else:
        recap[event.user]['cmd_nb'] += 1
    return recap

def summary_print(recap):
    print("#"*50)
    print("Global recap: \n")
    for user in recap:
        print(user + ": " + str(recap[user]['cmd_nb']) + " sudo command(s) used.")

regex = re.compile(r'(?P<month>([^\s]+))\s+'
                    r'(?P<day>([^\s]+))\s+'
                    r'(?P<timestamp>([^\s]+))\s+'
                    r'(?P<hostname>([^\s]+))\s+'
                    r'(?P<process>sudo)\[(?P<pid>\d+)\]:\s+'
                    r'(?P<user>\w+)\s:\s'
                    r'TTY=(?P<tty>([^\s]+))\s'
                    r';\sPWD=(?P<pwd>([^\s]+))\s'
                    r';\sUSER=(?P<sudo_user>([^\s]+))\s'
                    r';\sCOMMAND=(?P<command>([^\s]+))\s'
                    r'(?P<args>.*$)'
                  )

def search_sudo(logfile, recap):
    with logfile.open() as o_logfile:
        while True:
            logline = o_logfile.readline()

            if not logline:
                break

            match = regex.search(logline)
            if match:
                event = SudoEvent(match)
                event.sudo_print()
                recap = summary_update(recap, event)

recap = {}

for file in pathlib.Path("/var/log/").iterdir():
    if file.match('secure*'):
        search_sudo(file, recap)

summary_print(recap)