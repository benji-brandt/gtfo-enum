#!/usr/bin/python3
#Look up binary info in GTFO Bins
# Run the following commands on target machine and copy results to a file
# SUIDS: find / -perm -u=s -type f 2>/dev/null
# GUIDS: find / -perm -g=s -type f 2>/dev/null
# call > python3 gtfo-enum.py --file <filename>

import requests
import re
import sys
import getopt

bins = []
gtfoBase = 'https://gtfobins.github.io/gtfobins/'
h2reg = r"<h2 id=.*"
fileArg = ''
usage = 'Usage: python3 gtfo-enum.py --file <filename> [-a to show uses beyond SUID]'
allExploits = False
suid = 'SUID'
limSuid = 'Limited SUID'
#TODO link directly to the exploit listing?
# suidAnch = '#suid'
# limSUidAnch = '#limited-suid'

argv = sys.argv[1:]
try:
    opts, args = getopt.getopt(argv, "hf:a", ["file=", "help", "all"])
except getopt.GetoptError:
    print (usage)
    sys.exit(2)    
for opt, arg in opts:
    if opt in ('-h', '--help'):
        print (usage)
        sys.exit()
    elif opt in ("-f", "--file"):
        fileArg = arg
    elif opt in ('--all', '-a'):        
        allExploits = True
    else:
        print (usage)
        sys.exit(2)     
if not allExploits:
    print('\n~~~~ ONLY SHOWING BINARIES WITH SUID AND LIMITED SUID EXPLOITS ~~~~\n')
if fileArg == '':
    print (usage)
    sys.exit()
with open(fileArg) as binFile:
    lines = binFile.read().splitlines()
    for line in lines:
        index = line.rfind('/')
        bins.append(line[index+1:])
    binFile.close()

notFound = []
noSuid = []
for binName in bins:            
    resp = requests.get(gtfoBase + binName + '/')
    if resp.status_code != requests.codes.ok:
        if resp.status_code == 404:
            notFound.append(binName)
        else:
            print('~~~~~~~~~~~~~~~  ' + binName + '  ~~~~~~~~~~~~~~~\n')
            print('Error getting details! Status code: ' + str(resp.status_code) + '\n\n')
        continue
    exploitsFound = []
    exploits = re.findall(h2reg, resp.text)
    for exploit in exploits:
        startIndex = exploit.find('>')
        endIndex = exploit.rfind('<')
        exploitType = exploit[startIndex + 1 : endIndex]
        if exploitType in (suid, limSuid):
            exploitsFound.append(exploitType)
        elif allExploits:
            exploitsFound.append(exploitType)
    if (not allExploits) and (len(exploitsFound) == 0):
        noSuid.append(binName)
        continue
    print('~~~~~~~~~~~~~~~  ' + binName + '  ~~~~~~~~~~~~~~~\n')
    print(gtfoBase + binName + '/\n')
    print('This binary has the following entries: ')    
    for found in exploitsFound:
        print(found)           
    print('\n\n')
if not allExploits:    
    print('~~~~~~~~~~~~~~~  No SUID exploits  ~~~~~~~~~~~~~~~\n')    
    for missing in noSuid:
        print(missing)    
print('~~~~~~~~~~~~~~~  Not Found  ~~~~~~~~~~~~~~~\n')    
for missing in notFound:
    print(missing)
    
        
