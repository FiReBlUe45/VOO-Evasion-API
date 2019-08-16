"""
    evasion.py is an API which allows to detect and control an .évasion box from VOO
    Copyright (C) 2019 Vincent STRAGIER (vincent.stragier@outlook.com)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""
from __future__ import print_function
import argparse
import socket
import os
import sys

command = dict()
command["REMOTE_0"] = 58112
command["REMOTE_1"] = 58113
command["REMOTE_2"] = 58114
command["REMOTE_3"] = 58115
command["REMOTE_4"] = 58116
command["REMOTE_5"] = 58117
command["REMOTE_6"] = 58118
command["REMOTE_7"] = 58119
command["REMOTE_8"] = 58120
command["REMOTE_9"] = 58121
command["FAST_REVERSE"] = 58375
command["FAST_FORWARD"] = 58373
command["PLAY"] = 58368
command["MUTE"] = 57349
command["STAND_BY"] = 57344
command["STOP"] = 58370
command["RECORD"] = 58371
command["TV"] = 57360
command["VOD"] = 61224
command["GUIDE"] = 57355
command["INFO"] = 57358
command["MY_RECORDINGS"] = 61235
command["VIDEO_WALL"] = 61234
command["APPLICATION"] = 57352
command["BE_ON_DEMAND"] = 61236
command["BACK"] = 57346
command["HOME"] = 61184
command["VOL_UP"] = 57347
command["VOL_DOWN"] = 57348
command["UP"] = 57600
command["DOWN"] = 57601
command["LEFT"] = 57602
command["RIGHT"] = 57603
command["RED_KEY"] = 57856
command["BE_TV"] = 57359
command["OK"] = 57345

command_ls = list(command.keys())

# Allows to mask print() to the user
class manageVerbose:
    def __init__(self, verbose=True):
        self.verbosity = verbose
        
    def __enter__(self):
        if self.verbosity == False:
            self._original_stdout = sys.stdout
            sys.stdout = open(os.devnull, 'w')

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.verbosity == False:
            sys.stdout.close()
            sys.stdout = self._original_stdout

# Check the behaviour of the connection mechanism to detect the .evasion box(es)        
def isRFBandLikeVOOevasion(ip, port=5900, timeout=2, verbose=False):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as tcp:
        try:
            tcp.settimeout(timeout)
            tcp.connect((ip, port))
            serverMSG = tcp.recv(4096)
            
            if not serverMSG[0:3] == b'RFB':  # Not using RFB
                # print(serverMSG)
                return False

            tcp.send(serverMSG) # Continue the handcheck

            serverMSG = tcp.recv(4096)

            if not serverMSG == b'\x01\x01': # Security is not the same as on the .evasion box
                # print(serverMSG)
                return False

            tcp.send(b'\x01')
            serverMSG = tcp.recv(4096)

            if not serverMSG == b'\x00\x00\x00\x00': # ?? Error about security negociation
                return False

            tcp.send(b'\x01')
            serverMSG = tcp.recv(4096)

            if serverMSG == bytes(24):
                return True
            # print(len(serverMSG))
            return False
        
        except Exception as e:
            if verbose:
                print(e)
            return False

# Remove all the element corresponding to the "value_to_remove" from "the_list" and return a list
def purgeList(the_list, value_to_remove):
    temp = list()
    for i in the_list:
        if not i == value_to_remove:
            temp.append(i)
    return temp

# NOT WORKING
def commandToSetvolume(vol):
    VOL_DOWN = 57348
    VOL_UP = 57347
    cmd = list()

    for _ in range(21):
        cmd.append(VOL_DOWN)
    for _ in range(vol):
        cmd.append(VOL_UP)

    return cmd


# Adaptation of "isRFBandLikeVOOevasion()" for Pool
def isRFBandLikeVOOevasionPool(ip, port=5900, timeout=0.5, verbose=False):
    if isRFBandLikeVOOevasion(ip, port, timeout, verbose):
        return ip
    return 0

# Scan the default interface network (all the IPs on the  interface) to find .evasion box(es) and return a list of potential boxes.
def scanRFB():
    import netifaces
    import ipaddress
    from multiprocessing import Pool

    default_iface = netifaces.gateways()['default'][netifaces.AF_INET]
    addrs = netifaces.ifaddresses(default_iface[1])[netifaces.AF_INET]
    ls = list()

    for addr in addrs:
        mask = ipaddress.ip_address(addr["netmask"]) # Extract and compute subnet mask
        mask = format(int(mask), "32b")

        cnt_0 = 0
        cnt_1 = 0
        for bit in mask:
            if bit == "1" and cnt_0 == 0:
                cnt_1 += 1
            elif bit == "0":
                cnt_0 += 1
            else:
                cnt_1 = -1
                break
        
        if cnt_1 > 0:
            mask = str(cnt_1)
        else:
            print('Error, invalid mask address.')
        ip = addr["broadcast"].replace('255','0') + '/' + mask
        net =  ipaddress.ip_network(ip)
        
        # Base IP address
        print(net)

        addresses = list()
        
        for x in net:
            addresses.append(str(x))

        # Configure pool (scaling depend of the number of CPU)
        n = os.cpu_count()*25 #len(addresses)
        if n>256:
            n = 256
        print("Pool size (max=256): " + str(n))

        # Scan all the addresses with the help of a pool
        with Pool(n) as p:
            ls_evasion = p.map(isRFBandLikeVOOevasionPool, addresses)

        # Clean the results
        ls_evasion = purgeList(ls_evasion, 0)     
        print(ls_evasion)
        for ip in ls_evasion:
            ls.append(ip)

    print("Scan is done (" + str(len(ls)) + " address(es)).")
    return ls

# Display the list of valid know command (name and value)
def displayCommand():
    l = list(command.keys())
    l.sort()
    
    for cmd in l:
        print(cmd + " = " + str(command[cmd]))
    return

# Check the command validity (non case sensitive)
def isValidCommand(temp_command):
    if temp_command.upper() in command_ls:
        return True
    elif True:
        try:
            cmd = int(temp_command)
            if cmd in command.values():
                return True
            else:
                return False
        except:
            return False
            
    else:
        return False

# Convert a command (name or value to value)
def convertCommandToValue(temp_command):
    if isValidCommand(temp_command):
        try:
            return command[temp_command]
        except:
            return int(temp_command)

# Convert a command (value to name or name to value)
def convertCommand(temp_command):
    try:
        return command[temp_command]
    except:
        keys = list()
        if keys==None:
            print("NO KEY FOUND")
        for key, val in command.items():
            if val == int(temp_command):
                keys.append(key)
        if keys:
            temp_str = ' or '
            return temp_str.join(keys)
        
        raise NameError('Did not find the corresponding command name for this value')

# Check the "type" in the parser for the port
def type_port(astring):
    try:
        p = int(astring)
        if p >= 0 and p <= 65535:
            return astring
        else:
            raise argparse.ArgumentTypeError("Value should be an integer between 0 and 65535 included.")
    except:
        raise argparse.ArgumentTypeError("Value should be an integer between 0 and 65535 included.")

# Check the "type" in the parser for the command
def type_command(astring):
    if isValidCommand(astring):
        return astring
    else:
        raise argparse.ArgumentTypeError("Invalid command ('" + astring + "'), use '-lc' to list the valid commands")

# Display the security type of the RFB connection
def displaySecurityType(sec_type):
    switcher = {
        0: "Invalid",
        1: "NONE",
        2: "VNC Authentication"
    } 
    print(' security type: ' + str(sec_type) + ' (' + switcher.get(sec_type,"Not defined by IETF") +')' )

# Generate a bytes array with the command to send (KEYDOWN_KEY, KEYUP_KEY)
def genPacketFromCmd(cmd): #Set KEYUP, set KEYDOWN
    return b'\x04\x01\x00\x00' + (cmd).to_bytes(4, byteorder='big') + b'\x04\x00\x00\x00' + (cmd).to_bytes(4, byteorder='big')

# Convert a channel number in a sequence of command
def channelToCommand(ch):
    cmd_ls = list()
    try:
        ch_str = str(abs(ch))
    except Exception as e:
        print(e)
        exit(1)
    
    for c in ch_str:
        cmd_ls.append(convertCommandToValue('REMOTE_'+c))
    cmd_ls.append(convertCommandToValue('OK'))
    return cmd_ls

# Send the command to the defined address
def send_cmd(ip, port, cmd, timeout=None):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as vnc:
            print("1. Initialize connection to:\n IP: " + ip + "\n Port: " + str(port))
            if timeout and (type(timeout)==type(float()) or type(timeout)==type(int())):
                vnc.settimeout(timeout)
            vnc.connect((ip,5900))
            vnc_ver = vnc.recv(12)
            print("Receive RFB protocol version: " + str(vnc_ver))
            vnc.send(vnc_ver)
            print("Send back RFB protocol version: " + str(vnc_ver))
            print("2. Receive security")
            nb_sec_types = ord(vnc.recv(1))
            #print(nb_sec_types.decode())
            print("Nb security types: " + str(nb_sec_types))
            
            for _ in range(0, nb_sec_types):
                sec_type = ord(vnc.recv(1))
                displaySecurityType(sec_type)

            ClientInit = b'\x01' 
            print("3. Send ClientInit message: " + str(ClientInit)) # Send 1 byte
            vnc.send(ClientInit) # 0 -> Non exclusive connection, 1 -> exclusive connection
            ServerInit = vnc.recv(4096)
            print("Receive ServerInit: " + str(ServerInit))
            ClientEncodage = b'\x01' 
            print("4. Send Client to server message: " + str(ClientEncodage)) # Send 1 byte
            vnc.send(ClientEncodage)
            ServerClient = vnc.recv(4096)
            print("Receive from ServerClient: " + str(ServerClient))
            if type(cmd) == type(str()):
                print("5. Send command '" + str(cmd) + "': " + str(genPacketFromCmd(cmd)))
                vnc.send(genPacketFromCmd(cmd))
            elif type(cmd) == type(list()):
                if len(cmd)>1:
                    print("5. Send multiple commands:")
                else:
                    print("5. ", end="")
                
                for c in cmd:
                    print("Send command '"+ str(c) + "': " + str(genPacketFromCmd(c)))
                    vnc.send(genPacketFromCmd(c))
            else:
                raise NameError('In function send_cmd(), "cmd" should be a string or a list of string.')
            return True, None
    except Exception as e:
        print(e)
        return False, e

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", default=False,
                        help="increase output verbosity",
                        action="store_true")
    parser.add_argument("-f", "--find", default=False,
                        help="return a list of potential .evasion boxes.",
                        action="store_true")
    parser.add_argument("-s", "--status", default=False,
                        help="return 'success' if the command has been send else it return 'fail'.",
                        action="store_true")
    parser.add_argument("-a", "--address", type=str,
                        help="IP address of the .evasion box")
    parser.add_argument("-p", "--port", type=type_port, default=5900,
                        help="port of the .evasion box, default is 5900 [optional]")
    parser.add_argument("-c", "--command", type=type_command, nargs='+',
                        help="command to send to the .evasion box (the command is checked), name of the command and value are accepted")
    parser.add_argument("-ch", "--channel", type=int,
                        help="send the command to the .evasion box to change the channel (must be an integer)")
    # NOT WORKING
    #parser.add_argument("-vol", "--volume", type=int,
    #                    help="send the command to the .evasion box to change the volume (must be an integer [0-20])")
    # Not implemented
    #parser.add_argument("-rc", "--raw_command", type=int,
    #                    help="raw command wich will be send to the .evasion box (will be send as it is without check), must be an integer")
    parser.add_argument("-cv", "--convert_command", type=type_command, nargs='+',
                        help="convert a valid command from name to value or from value to name")
    parser.add_argument("-lc", "--list_commands",
                        help="display the list of known commands",
                        action="store_true")
    
    args = parser.parse_args()

    if args.verbose:
        print("Python 3 based .evasion box API")
        print("Verbosity turned on.\n")
        print("Arguments:\n")
        for arg, value in vars(args).items():
            print("'" + arg + "': " + str(value))
        print()
             
    if args.list_commands:
        if args.verbose:
            print("Display the list of valid know command for the .evasion box:\n")
        displayCommand()
        
    if args.convert_command:
        for cmd in args.convert_command:
            with manageVerbose(args.verbose):
                print(cmd + ": ", end='')
            print(convertCommand(cmd.upper()))

    if args.find:
        print("Start scanning network (this is a CPU intensive task, which needs the 'netifaces' module):")
        with manageVerbose(args.verbose):
            evasion = scanRFB()

        if len(evasion) > 0:
            if len(evasion) == 1:
                print("Potential .evasion box:")
            else:
                print("Potential .evasion boxes:")
            for box in evasion:
                print("IP: " + box)
        else:
            print("No box have been found.")

    if args.address and args.channel:
        try:
            with manageVerbose(args.verbose):
                cmd_ls = channelToCommand(args.channel)
                print(cmd_ls)
                result, error = send_cmd(args.address, args.port, cmd_ls)
                    
            if result and (args.status or args.verbose):
                print('Success')
            elif args.status or args.verbose:
                print('Fail')
                if args.verbose:
                    print(error)

        except Exception as e:
            print(e)

    """
    NOT WORKING
    if args.address and args.volume:
        try:
            with manageVerbose(args.verbose):
                cmd_ls = commandToSetvolume(args.volume)
                print(cmd_ls)
                result, error = send_cmd(args.address, args.port, cmd_ls)
                    
            if result and (args.status or args.verbose):
                print('Success')
            elif args.status or args.verbose:
                print('Fail')
                if args.verbose:
                    print(error)
            
        except Exception as e:
            print(e)
    """

    if args.address and args.command:
        try:
            cmd_ls = list()
            for cmd in args.command:
                cmd_ls.append(convertCommandToValue(cmd.upper()))

            with manageVerbose(args.verbose):
                print(cmd_ls)
                result, error = send_cmd(args.address, args.port, cmd_ls)
                    
            if result and (args.status or args.verbose):
                print('Success')
            elif args.status or args.verbose:
                print('Fail')
                if args.verbose:
                    print(error)
            
        except Exception as e:
            print(e)
            
    
    """
    # Create a socket to be used a client

    socket.setdefaulttimeout(10)

    timeout = socket.getdefaulttimeout()

    print("System has default timeout of {} for create_connection".format(timeout))

    
    with socket.create_connection(("192.168.0.15",5900)) as s:
        print("connected")
        bytes2Send = str.encode("Hello server system!")
        # s.sendall(bytes2Send)
        # Receive the data

        data = s.recv(1024)

        print(data)
    """
if __name__ == '__main__':
    main()
