#!/usr/bin/env python3
import sys
import requests
import json
import os  
import ipaddress
import traceback

#Minimal number of reports before alerting
MIN_REP=10
keysFile = "./apiKey.txt"


url = 'https://api.abuseipdb.com/api/v2/check'
querystring = {'ipAddress': '1.1.1.1','maxAgeInDays': '90'}

#Functions

# GetApiKey
# Reads ABUSEIPDB ApiKey from a file called apiKey.txt stored in the execution rute.

def getApiKey(filename):
    try:
        with open(filename, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        print("'%s' file not found" % filename)
        exit()

# Is_IPv4
# Checks if something is a real IPv4
def is_ipv4(string):
    try:
        ipaddress.IPv4Network(string)
        return True
    except ValueError:
        return False
# Is_Private
# Checks if the IP is private
# The idea is to not waste API requests
def is_private(string):
    return ipaddress.ip_address(string).is_private  

# The IP File suld be specified on the execution line
if len(sys.argv) > 1:
    file_name = sys.argv[1]
else:
    print("Execute as follows: abuseCheck.py <IP_LIST_FILE>")
    exit()


headers = {'Accept': 'application/json','Key': getApiKey(keysFile)}

# Output file creation
fil1 = open (os.path.splitext(file_name)[0]+'_complete.txt', 'w')
fil1.close()
fil2 = open(os.path.splitext(file_name)[0]+'_summary.txt', 'w')
fil2.write("ipAddress,abuseConfidenceScore,countryCode,usageType,isp,domain,totalReports"+"\n")
fil2.close()
with open(file_name) as fp:
    #print(fp.readline())
    lines = fp.readlines()
    
    for line in lines:
        line = line.strip()
        querystring = {'ipAddress': line,'maxAgeInDays': '90'}
        if is_ipv4(line):
            if not is_private(line):
                resp = requests.request(method='GET', url=url, headers=headers, params=querystring)
            else:
                print("[ERROR] IP Privada: " +line )
                continue
        else:
            print("[ERROR] No es una IP: " + line)
            continue

        decodedResponse = json.loads(resp.text)
        try:
            print(decodedResponse.get("data").get("ipAddress") + "," + str(decodedResponse.get("data").get("abuseConfidenceScore")))
        except AttributeError:
            print("[ERROR] La siguiente IP no se puede consultar: " + line)
            continue
        
        try:
            if decodedResponse.get("data").get("abuseConfidenceScore") > MIN_REP:
                with open(os.path.splitext(file_name)[0]+'_complete.txt', 'a') as writer:
                    writer.write(json.dumps(decodedResponse, sort_keys=True, indent=4))
                    print(json.dumps(decodedResponse, sort_keys=True, indent=4))
        except Exception:
            traceback.print_exc()

        try:    
            with open(os.path.splitext(file_name)[0]+'_summary.txt', 'a') as writer2:
                writer2.write(str(decodedResponse.get("data").get("ipAddress")) + ",")
                writer2.write(str(decodedResponse.get("data").get("abuseConfidenceScore")) + ",")
                writer2.write(str(decodedResponse.get("data").get("countryCode")) + ",")
                writer2.write(str(decodedResponse.get("data").get("usageType")) + ",")
                writer2.write(str(decodedResponse.get("data").get("isp")) + ",")
                writer2.write(str(decodedResponse.get("data").get("domain")) + ",")
                writer2.write(str(decodedResponse.get("data").get("totalReports")) + "\n")
        except Exception:
            traceback.print_exc()
            continue
    
    print("File created at: " + os.path.splitext(file_name)[0] + "_complete.txt")
    print("File created at: " + os.path.splitext(file_name)[0] + "_summary.txt")
