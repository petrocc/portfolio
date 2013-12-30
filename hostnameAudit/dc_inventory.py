#!/usr/bin/env python 

# Data Center Invetory
# This uses several datasources, including ssh into each machine reachable 
# to generate an inventory

# Standard Modules: 
import csv, os
import socket
import re
import threading
import Queue
from ping import *
import popen2
import pickle

# Non-standard:
import dns.zone   # dnspython module from http://www.dnspython.org
import dns.query  # dnspython module from http://www.dnspython.org


# Custom stuff:
import resultsParser

DEBUG=False

# These first couple will eventually be overrideable from the command line: 
output_file='inventory'
dnsoutput="dns_report"
output_format='csv'
exception_file='exceptiontable.csv'
output_extension=output_format

# This is a flag as to whether write out ilo and mgmt stuff we cannot correlate with a server: 
writeMissing=True

# This is the IP address of the dns server we're allowed to do a zone-xfer from: 
dns_server='1.1.1.1'  # Disabled. 

# for my own diabolical porpoises I split what we're interested in into "work" and "mgt". 
# This is because most "work" nodes will have something in one or both of the "mgt" nodes. 

work_zones=['testing','development'] # Disabled
mgt_zones=['mang'] # Disabled 
zone_append='main.zone'

# Some regular expressions: 
#
a_record=re.compile('(?P<name>\S+)\s+.*IN A\s+(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
cname_record=re.compile('(?P<cname>\S+)\s+.*IN CNAME\s+(?P<name>\S+)')

ssh_errors=re.compile('ssh:.*port 22: (?P<sshError>.*)$')

permission_denied=re.compile('permission denied', re.I)

# How many working threads for the pings and the various OS checks:
thread_num=15

hostQueue=Queue.Queue()
doneQueue=Queue.Queue()
done_list={}
ssh_error_list={}


hostIDs={}

class ssh_check(threading.Thread):
    def __init__(self,queue,done_list,threadID):
        threading.Thread.__init__(self)
        self.queue=queue
        self.done_list=done_list
        self.threadID=threadID

    def run(self):
        while True:
            whatOS=''
            results=''
            ip=''
            try:
                ip=self.queue.get()
            except:
                if not ip:
                    ip='127.0.0.3'
            if not ip:
                ip='127.0.0.2'
            what_os_string='ssh -o PasswordAuthentication=no -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no %(ip)s \'uname -s\'' %vars()
            sunos_ssh_string='ssh -o PasswordAuthentication=no -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no %(ip)s \'i=`ifconfig -a` ; h=`hostid` ; echo "server=`hostname`" ; echo "network=$i"; echo "type=`uname -s`"; echo "dmidecode=$d";echo "hostid=$h"\'' %vars()
            linux_ssh_string='ssh -o PasswordAuthentication=no -o ConnectTimeout=3 -o BatchMode=yes -o StrictHostKeyChecking=no %(ip)s \'i=`ifconfig` ; h=`hostid` ; d=`dmidecode -t1` ; echo "server=`hostname`" ;echo "type=`uname -s`"; echo "network=$i"; echo "dmidecode=$d";echo "hostid=$h"\'' %vars()

            # Firs a ping check, because it's cheaper. 
            try:
                #  "do_one" is a function inside ping.py
                a=do_one(ip,1)
                if a==None:
                    a=do_one(ip,1)
            except:
                a=None

            # If we can ping it, then we try the SSH: 
            if a is None:
                results='error: no ping'
            else:
                r,w,e=popen2.popen3(what_os_string)
                whatOS=r.readlines()
                if len(whatOS) == 1:
                    whatOS=whatOS[0]
                
                errs=e.readlines()
                w.close()
                r.close()
                e.close()
                #que=w.readlines()
                for each in errs:
                    if ssh_errors.search(each):
                        whatOS='connection failed'
                        this_error=ssh_errors.search(each).group('sshError')
                        this_error=this_error.strip()
                        results="error: %(this_error)s" %vars()
                        ssh_error_list[ip]=errs
                    elif permission_denied.search(each):
                        whatOS='connection failed'
                        results='error: %(ip)s permission denied' %vars()
                        ssh_error_list[ip]=errs
                
                if 'SunOS' in whatOS:
                    r,w,e=popen2.popen3(sunos_ssh_string)
                    results=r.readlines()
                    errs=e.readlines()
                    w.close()
                    r.close()
                    e.close()
                    doneQueue.put([ip,results])
                elif 'Linux' in whatOS:
                    r,w,e=popen2.popen3(linux_ssh_string)
                    results=r.readlines()
                    errs=e.readlines()
                    w.close()
                    r.close()
                    e.close()
                    doneQueue.put([ip,results])
                elif whatOS == 'connection failed':
                    if len(results) > 0: 
                        pass
                    else:
                        results="some error in logic got us here"
                else:
                    results='error: ssh unknown error %(whatOS)s, %(ip)s' %vars()

            doneQueue.put([ip,results])
def gather_host_data():
    """ This bit attemts to gather certain host data (OS type, MAC addresses 
etc.) from each host.
input is:
{'context': '', 'short_name': '', '': '', 'pro_dip': '', 'ilo_name': '', 'mgt_ip': '', 'cnames': '', 'mgt_name': ''}

"""
    # Trim off header line if it looks like what it's supposed to: 
    if 'header' in full_list.keys():
        del full_list['header']
    done_list=[]
    # This sets up the threads: 
    for i in range(thread_num):
        checkThread=ssh_check(hostQueue,done_list,i)
        checkThread.setDaemon(True)
        checkThread.start()

    for server_entry in full_list: 
        server_line=full_list[server_entry]
        # So for each line in the "full list" of stuff we grabbed from DNS,
        # we take the short name, the "pub" ip and the mgt ip. 
        
        # If we have a mgt IP we use that, otherwise we use the pub ip.
        # If neither of those work we create condition to print an error later. 
        if full_list[server_entry]['mgt_ip']:
            connect_ip=full_list[server_entry]['mgt_ip']
        elif full_list[server_entry]['prod_ip']:
            connect_ip=full_list[server_entry]['prod_ip']
        else:
            print "%(sn)s does not have any IPs associated with it" %vars()

        #then we shove this into the hostQueue. 
        if connect_ip == None:
            print sn + " has no IP addresses. This is an error and an error message."
        else:
            if full_list[server_entry]['mgt_ip'] in  exception_list.keys():
                ex_ip=full_list[server_entry]['mgt_ip']
                full_list[serer_entry]['exception']=exception_list[ex_ip]['reason']
            elif full_list[server_entry]['prod_ip'] in exception_list.keys():
                ex_ip=full_list[server_entry]['prod_ip']
                full_list[server_entry]['exception']=exception_list[ex_ip]['reason']
            else:
               hostQueue.put(connect_ip)

    wait_for_hqueue=True
    while wait_for_hqueue:
        if hostQueue.qsize() == 0: # So check to see if the queue is empty. 
            time.sleep(4)         # If it is, take a nap. 
            if hostQueue.qsize() == 0: # If it's still empty
                wait_for_hqueue=False  # call it good. 
        if DEBUG: print "^", doneQueue.qsize(), hostQueue.qsize()
        time.sleep(1)

    lots_of_stuff={} # This is a bucket to store the stuff coming back from the host scrape. 
    wait_for_dqueue=True
    while doneQueue.qsize() > 0:
        stuff=doneQueue.get()
        ip=stuff[0]
        data=stuff[1]
        lots_of_stuff[ip]=data
        if DEBUG: print "v",doneQueue.qsize()

    return lots_of_stuff


def read_exceptions(file):
    """This takes the name of a CSV file that stores exceptions 
        and returns a list of [shortname,ip] """
    csvreader=csv.reader(open(file,'r'), delimiter=',')
    data={}
    import time
    for row in csvreader:
        if row[0]=='full name':
            pass
        else:
            try:
                main_ip=socket.gethostbyname(row[0])
            except:
                main_ip=row[4]
            if not main_ip in data:
                try:
                    data[main_ip]={'iloname':row[1],'iloip':row[2],'mgtname':row[3],'mgt_ip':row[4],'reason':row[5]}
                except:
                    print "Exception a:", row
            else:
                print "Other exception", main_ip,data[main_ip], row
    return data

def AXFR(zone, dns_server):
    """this uses the dnspython module from http://www.dnspython.org. We use it
    to do a zone transfer from a designated DNS server, and then extract the bits
    we are interested in--name to IP and name to cname."""

    # So this 
    # is a little messed up as there's no direct way to call dns.whatever and just get a list
    # We do a zone transfer query, then turn it into a zone, then extract it a as text and 
    # parse that text. Might as well be reading it from a file :( 
    #
    # We then create a dictionary/hash that is ip->address and ip->cname and give those back. 
    this_zone=dns.zone.from_xfr(dns.query.xfr(dns_server,zone))
    name_ip_pairs={}
    cname_pairs={}
    for item in this_zone:
        line=this_zone[item].to_text(item)
        if a_record.match(line):
            name_ip_pairs[a_record.match(line).group('name')]=a_record.match(line).group('ip')
        elif cname_record.match(line):
            cname_pairs[cname_record.match(line).group('name')]=cname_record.match(line).group('cname')
    return name_ip_pairs,cname_pairs

def screen_print_non_matches(zone,non_matches):
    print "----",zone
    for key in non_matches:
        print key, non_matches[key]

def csv_out(data,output_file,output_extension='csv'):
    
    filename=output_file + "." + output_extension
    writer=csv.writer(open(filename,"wb"),dialect='excel')
    if type(data) == type([]): # If this is a list do: 
        for line in data:
            writer.writerow(line)
    elif type(data) == type({}): # If it's a dictionary try:
        if 'header' in data.keys():
            writer.writerow(data['header'])
            del data['header']
            for key in data:
                value=data[key]
                writer.writerow(value)
        else:
            for key in data:
                value=data[key]
                writer.writerow([key,value])
            
    return

def write_inventory(data,file_name,extension='csv'):
    """This writes the final inventory in some reasonable order
    ['hostID', 'context', 'short_name', 'ilo_ip', 'hostType', 'ilo_name', 'reachable', 'mgt_ip', 'cnames', 'prod_ip', 'mgt_name']
    """ 

    filename=file_name + "." + extension
    writer=csv.writer(open(filename,"wb"),dialect='excel')

    header=['context','short_name','prod_ip','cnames','short_name','mgt_name','mgt_ip','ilo_name','ilo_ip','hostType','machineType','reachable','hostID','sku','serialNumber','uuid','product name',"networkDetails" ]
    writer.writerow(header)
    for ip in data:
        
        list=[]
        server=data[ip]
        if server.has_key('exception'):
            header.append('exception')
            
        for head in header:
            if head=='networkDetails' and server.has_key(head) and server[head] != 0: 
                for net_iface in server[head]:
                    iface=server[head][net_iface]
                    if iface.has_key('bondstate'):
                        bondstate=iface['bondstate']
                    else:
                        bondstate=''
                    ip=iface['ip']
                    if iface.has_key('hwaddr'):
                        hwaddr=iface['hwaddr']
                    else:
                        hwaddr='00000000'
                    list.append(net_iface)
                    bondstate='bond: %(bondstate)s' %vars()
                    list.append(bondstate)
                    list.append(ip)
                    list.append(hwaddr)
            else:
                try:
                    if not server[head]: 
                        list.append('-')
                    else:
                        list.append(server[head])
                except:
                    list.append('x')
        
        if ssh_error_list.has_key(ip):
                error_list=ssh_error_list[ip]
                if type([]) == type(error_list):
                    for each in error_list:
                        each=each.strip()
                        list.append(each)
                else:
                    list.append(error_list)
                    
        writer.writerow(list)
    
        

    return

def write_ssh_errors(ssh_errors_list):
    ''' print out ssh error list. Needs to be more flexible'''

    fp=open('ssh_error_list.txt','w')
    for ip in ssh_errors_list:
        if full_list.has_key(ip):
            host=full_list[ip]['short_name']
        errors=ssh_errors_list[ip]
        ip_l="%(ip)s, %(host)s\n" %vars()
        fp.write(ip_l)
        if type(errors) == type([]):
            for line in errors:
                line="     %(line)s" %vars()
                fp.write(line)
        else:
            errors_l="     %(errors)s" %vars()
            fp.writeline(errors)
    return


'''
So what we're looking for is a chart of:

short name | context | cname | pub-ip | mgt name | mgt ip | ilo name | ilo ip
'''

# First we grab the management stuff:
mgt_ip_list,mgt_cname=AXFR('mgt'+'.'+zone_append,dns_server)

# We make a copy because we're going to delete out of this and report on it.
mgt_ip_nomatch=mgt_ip_list.copy()


# Doing the same for ILO: 
ilo_ip_list,ilo_cname=AXFR('ilo'+'.'+zone_append,dns_server)

# We make a copy because we're going to delete out of this and report on it as well.
ilo_ip_nomatch=ilo_ip_list.copy()


# Note that the exception list is a mix of ilo and managment IPs. 
# Consult the list for the reason stuff is in there. 
exception_list=read_exceptions(exception_file)

# Then the rest of them.
full_list={}
problems=[]
short_names=[]

for zone in work_zones:
    full_zone=zone + "." + zone_append
    ip,cn=AXFR(full_zone,dns_server)
    for short_name in ip.keys():
        if short_name in cn.keys():
            commonname=cn[short_name]
            cname_mgt=commonname+'-'+zone
        else:
            commonname=''
            cname_mgt=''
        # both ilo and mgt use <short>-<zone> for their name: 
        mgt_name=short_name + '-' + zone
        ilo_name=short_name + '-' + zone

        # so what we're doing here is seeing if we can match the "normal" 
        # pattern to something in the mgt zone. If there is we remove it 
        # from the mgt_ip_nomatch list 
        if mgt_name in mgt_ip_list:
            del mgt_ip_nomatch[mgt_name]
            mgt_ip=mgt_ip_list[mgt_name]
        elif cname_mgt in mgt_ip_list:
            del mgt_ip_nomatch[cname_mgt]
            mgt_ip=mgt_ip_list[cname_mgt]
            mgt_name=cname_mgt
        else:
            mgt_name=''
            mgt_ip=''

        # The same thing for ilos: 
        if ilo_name in ilo_ip_list:
            del ilo_ip_nomatch[ilo_name]
            ilo_ip=ilo_ip_list[ilo_name]
        else:
            ilo_name=''
            ilo_ip=''

        if mgt_ip:
            key_ip=mgt_ip
        elif ip[short_name]:
            key_ip=ip[short_name]
        else:
            print "%(sn)s does not have any IPs associated with it" %vars()

        full_list[key_ip]={'short_name':short_name,'context':zone,'cnames':commonname, 'prod_ip':ip[short_name],'mgt_name':mgt_name,'mgt_ip':mgt_ip,'ilo_name':ilo_name,'ilo_ip':ilo_ip}

        # This is to clear out the variables for the next round: 
        commonname=''
        mgt_name=''
        mgt_ip=''
        ilo_name=''
        ilo_ip=''



### Now let's clear out the stuff in the exception list. We'll publish that list seperately: 

for entry in exception_list: 
    exception=exception_list[entry]
    if exception['iloname'] in ilo_ip_nomatch.keys():
        del ilo_ip_nomatch[exception['iloname']]
    if exception['mgtname'] in mgt_ip_nomatch.keys():
        del mgt_ip_nomatch[exception['mgtname']]

final_table={}

if os.geteuid() == 0:
    #Uncomment this to run for real 
    host_data=gather_host_data()
    # Uncomment these to generate test data
    pickle.dump(host_data,open('host_data','w'))
    
    #comment this out "for real"
    # host_data=pickle.load(open('host_data'))
    remainder_list=full_list.copy()

    delete_data=host_data.copy()
    for host in host_data:
        ssh_output=host_data[host]
        hostDetails=resultsParser.resultsParser(host,ssh_output)
        # ['network', 'dmiDetails', 'ip', 'fqdn', 'hostType', 'reachable']
        try:
            networkDetails=hostDetails['network']
            dmiDetails=hostDetails['dmiDetails']
            ip=hostDetails['ip']
            fqdn=hostDetails['fqdn']
            reachable=hostDetails['reachable']
            hostType=hostDetails['hostType']
            hostID=hostDetails['hostID']
        except:
           print 'detail_load:', host, hostDetails 
        #if not networkDetails == 0  :
        #    for interface in networkDetails:
        #        if networkDetails[interface]['ip']:
        #            print 'Network', interface #, networkDetails[interface]['ip']
        if not reachable:
            reachable='-no-'
        if not hostID:
            hostID='--'
        full_list[ip]['networkDetails']=networkDetails
        full_list[ip]['hostType']=hostType.strip()
        full_list[ip]['hostID']=hostID
        full_list[ip]['reachable']=reachable
        
        # For VMs: 
        if (len(dmiDetails) > 0) and (dmiDetails['Manufacturer'] == 'VMware, Inc.'):
            sku=''
            serialNumber=dmiDetails['Serial Number'].strip()
            uuid=dmiDetails['UUID']
            machineType='VM'
        # For HP Hardware: 
        elif (len(dmiDetails) > 0) and (dmiDetails['Manufacturer'] == 'HP'):
            sku=dmiDetails['SKU Number']
            serialNumber=dmiDetails['Serial Number'].strip()
            uuid=dmiDetails['UUID']
            productName=dmiDetails['Product Name']
            machineType=re.sub('ProLiant ','',productName)
        elif hostType=='SunOS':
            sku=''
            serialNumber=' '
            uuid=''
            machineType='Sun'
        elif hostType=='unk':
            sku=''
            serialNumber=''
            uuid=''
            machineType=' '
        elif len(dmiDetails)>0:
            sku=''
            serialNumber=''
            uuid=''
            machineType='WTF'
            print "WTF:", hostType, dmiDetails
        elif reachable=='yes':
            sku=''
            serialNumber=''
            uuid=''
            machineType=''
            print "t", hostDetails, hostType
        else:
            sku=''
            serialNumber=''
            uuid=''
            productName=''
            print "here", hostDetails

        full_list[ip]['sku']=sku
        full_list[ip]['serialNumber']=serialNumber
        full_list[ip]['uuid']=uuid
        full_list[ip]['machineType']=machineType

        if hostID:
            key=hostID
        elif len(dmiDetails) > 0 and "UUID" in dmiDetails:
            key=dmiDetails['UUID']
        else:
            key=hostDetails['fqdn']


        if remainder_list.has_key(ip):
            del remainder_list[ip]
            print ip
            del delete_data[host]
        elif ip in full_list:
            print "not in remainder, but in full"
        else: 
            print "%(ip)s is not there" %vars()
            
    for i in remainder_list:
        print "remainder_list:", i, remainder_list[i]
    for i in delete_data:
        print "leftover from data",i, delete_data[i]
    
else:
    print "Not running as root, can't check hosts"

write_inventory(full_list, output_file)
pickle.dump(full_list,open('full_list','w'))

if writeMissing:
    csv_out(mgt_ip_nomatch,"mgt-non-match")
    csv_out(ilo_ip_nomatch,"ilo-non-match")

write_ssh_errors(ssh_error_list)
