#!/usr/bin/env python

import re, sys, os
import socket, struct
import pickle
import ConfigParser



def resultsParser(ip,ssh_output):
    '''This takes output from the ssh session and returns data in a useful form'''
    ### Some useful regular expressions: 
    # At the beginning of the line (^) look for a word (\w) of one or more characters (+)
    # followed by whitespace. We also look for virtual interfaces with a :\d+ 
    interface_line=re.compile('^(?P<iface>\w+|\w+:\d+)\s.*')

    # this is just to extract the MAC. We look for  HWaddr (\s.*) then we look for the hardware address 
    # (\S+, whcih basically means "one or more non-whitespace"
    hardware=re.compile('.*hwaddr (?P<hwaddr>\S+)',re.IGNORECASE)

    # IP address and netmask (we don't care about bcast:
    netwreck=re.compile('inet addr:(?P<ipaddr>\S+)\s.*Mask:(?P<netmask>\S+)')

    # Checking for master or slave: 
    bonds=re.compile('(?P<bondState>master|slave)',re.IGNORECASE)
    
    # This is what ifconfig -a looks like on a sun box: 
    #lo0:1: flags=2001000849<UP,LOOPBACK,RUNNING,MULTICAST,IPv4,VIRTUAL> mtu 8232 index 1
    #        inet 127.0.0.1 netmask ff000000 
    #nxge0:1: flags=1000843<UP,BROADCAST,RUNNING,MULTICAST,IPv4> mtu 1500 index 2
    #        inet 10.65.194.117 netmask fffffc00 broadcast 10.65.195.255
    #nxge1:2: flags=1000843<UP,BROADCAST,RUNNING,MULTICAST,IPv4> mtu 1500 index 3
    #        inet 10.65.102.104 netmask ffffffe0 broadcast 10.65.102.127
    # This regex works, with a little fudging: 
    sunosifconfig=re.compile('(?P<iface>\S+).*inet (?P<ipaddr>\d+\.\d+\.\d+\.\d+) netmask\s+(?P<netmask>\S+)')

    # The six types of data we get back from our ssh check: 
    hostnameextract=re.compile('^server=(?P<hostName>\S+)')
    unameextract=re.compile('^type=(?P<uname>\S+)')
    networksign=re.compile('network=') # With this one we're not looking to extract anything, this is just a signpost. 
    dmisign=re.compile('dmidecode=')

    error=re.compile('^error: (?P<ssherror>\S+)')

    hostIDextract=re.compile('^hostid=(?P<hostId>\S+)$')

    # These are for parsing the returns from dmidecode -t1: 
    colon=re.compile('^\s(?P<key>.*):\s(?P<value>.*)$')
    symbios=re.compile('^SMBIOS\s(?P<smbiosversion>\d.*)$')

    # The ifconfig ouput is really nice about putting a blank line between interfaces:
    blankLine=re.compile('^$')

    # This is where we store stuff: 
    details={}

    def split_ifconfig_output(lines,osType):
        """This is a list of stuff returned from running the "ifconfig" command: """ 
        # some variables for tracking where we are: 
        interfaces={}
        interface=''
        bondage=''
        ip=''
        netmask=''
        hwaddr=''
        if osType=="Linux":
            for line in lines: 
                if interface_line.match(line):
                    match=interface_line.match(line)
                    interface=match.group('iface')
                    if hardware.search(line):
                        h=hardware.search(line)
                        hwaddr=h.group('hwaddr')
                    else:
                        hwaddr='loop'
                elif bonds.search(line):
                    bondage=bonds.search(line).group('bondState')
                elif netwreck.search(line):
                    ip=netwreck.search(line).groups()[0]
                    netmask=netwreck.search(line).groups()[1]
                elif blankLine.match(line):
                    if interface != "lo":
                        interfaces[interface]={'bondState':bondage, 'ip':ip,'netmask':netmask,'hwaddr':hwaddr}
                        interface=''
                        bondage=''
                        ip=''
                        netmask=''
                        hwaddr=''
        elif osType=='SunOS':
            testline=''
            for line in lines:
                if testline=='':
                    testline=line.strip()
                else:
                    testline=testline+line.strip()
                if sunosifconfig.match(testline):
                    interface=sunosifconfig.match(testline).group('iface')
                    ip=sunosifconfig.match(testline).group('ipaddr')
                    netmask=sunosifconfig.match(testline).group('netmask')
                    if "lo" not in interface: 
                        interfaces[interface]={'bondstate':'na','ip':ip,'netmask':netmask, 'hwaddr':'na'}

                    netmask=''
                    hwaddr=''
                    ip=''
                    testline=''
                else:
                    testline=line.strip()
        return interfaces


##    def __init__(self, hostData):

    def printdata(details):

        print len(details)

        for serverName in details:
            print serverName
            print details[serverName]


    def dmidecode_parse(dmiDecode):
        """ Converts the output of dmidecode -t1 to something useful """ 
        returnDict={}
        for line in dmiDecode:
            if colon.match(line):
                key=colon.match(line).group('key')
                value=colon.match(line).group('value')
                returnDict[key]=value
            elif symbios.match(line):
                key="symbiosVers"
                value=symbios.match(line).group('smbiosversion')
        return returnDict




    fqdn=socket.gethostbyaddr(ip)[0]
    inNetworkLines=False # Flag for network lines.
    networkLines=[] # Storage container for ssh_outputhem. 
    dmiFlag=False # Flag for dmidecode lines
    dmiDecodeLines=[]
    host_name=''
    host_type=''
    hostID=''

    # We pass back "no ping" and "ssh unresponsive" if we can't ping or can't ssh in. 
    # ssh_output catches that: 
    if isinstance(ssh_output,str):
        if error.match(ssh_output):
            details={'fqdn':fqdn, 'reachable':'ssh fails', 'ip':ip, 'hostType': 'unk', 'network':0, 'dmiDetails':{}, 'hostID':hostID,"d":1}
        else:
            details={'fqdn':fqdn, 'reachable':'no ssh', 'ip':ip, 'hostType': 'unk', 'network':0, 'dmiDetails':{}, 'hostID':hostID,"d":2}
            print "resultsparser line 156", fqdn, ssh_output
    else:
        # In here we break the various checks down into dictionaries 
        for line in ssh_output:
            if hostnameextract.match(line):
                host_name=hostnameextract.match(line).group('hostName')
            elif unameextract.match(line):
                host_type=unameextract.match(line).group('uname')
                if host_type=='SunOS;':  # because I see this and I want it gone. UGLY!
                    host_type='SunOS'
            elif networksign.match(line):
                line=networksign.sub('',line) # this is necessary because the 0th interface contains the "network=" leader.
                inNetworkLines=True
                networkLines.append(line)
            elif hostIDextract.match(line):
                hostID=hostIDextract.match(line).group('hostId')
            elif dmisign.match(line):
                inNetworkLines=False
                dmiFlag=True
                dmiDecodeLines.append(line)
            elif inNetworkLines==True:
                networkLines.append(line)
            elif dmiFlag:
                dmiDecodeLines.append(line)
            else:
                print "This shouldn't be:", line.strip()
        networkDetails=split_ifconfig_output(networkLines, host_type)
        if host_type == 'Linux':
            dmiDetails=dmidecode_parse(dmiDecodeLines)
        elif 'SunOS' in host_type:
            dmiDetails = {'Product Name': 'SunOS', 'Manufacturer': 'Sun'}
        else:
            if len(dmiDecodeLines) > 0:
                dmiDetails=dmidecode_parse(dmiDecodeLines)
            print "resultsparser:", host_type, dmiDecodeLines, fqdn
        details = {'fqdn':fqdn,'ip':ip, 'reachable':'yes', 'hostType': host_type, 'network':networkDetails, 'dmiDetails':dmiDetails,'hostID':hostID }
    return details
# End of class 
