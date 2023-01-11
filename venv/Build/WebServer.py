from markupsafe import escape
from flask import Flask, render_template, redirect, url_for, request, session, send_file
from datetime import timedelta, date, datetime
import requests
import json
from random import randint
import random
import string
import shutil
import logging
from logging.handlers import RotatingFileHandler
from zipfile import ZipFile

app = Flask(__name__)

#logging.basicConfig(filename="Logs\ProcessLog", level=logging.DEBUG,format="%(asctime)s %(message)s")
#logging.basicConfig(filename="/home/pi/API-Webpage/venv/Build/Logs/ProcessLog", level=logging.DEBUG,format="%(asctime)s %(message)s")
logger = logging.getLogger("Rotating Log")
logger.setLevel(logging.ERROR)

#path="Logs\Process.log"
path="/home/pi/API-Webpage/venv/Build/Logs"
handler = RotatingFileHandler(path, maxBytes=2000000,backupCount=5)

formatter = logging.Formatter('%(asctime)s - %(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)

class apiInfo:
    headers = {
        'Accept': 'application/json',
        'X-AUTH-TOKEN': ''
    }
    #Partitionid = {"9KqISNFnQ8W_KgcAnXAQiA"}               #albion partition
    Partitionid = {"kT8A3FFXSQuWCbxs58Iiug","Q8MUf4fWRkuckIhWMcUg1w"}                 # lumen/ whole foods
    Accountid = []
    accountName = []
    sipPort = ''
    sipPort2 = ''
    mac = ''
    prt = []
    actName = []
    firstname = ''
    lastname = ''




def mult_config_template(Partitionid, Accountid, headers, usernames, passwords, sipPort, mac, sipPort2):
    total = [1, 2]
    for prt in Partitionid:
        for act in Accountid:
            for deviceNum in total:
                line = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/" + act, headers=headers)
                l = json.loads(line.text)
                logger.error("Configure Multi Template:" + str(l))
                # print("3:")
                # print(l)
                if line.status_code == 401:
                    if l["messages"] == 'ExpiredAuthToken':
                        return redirect(url_for('logout'))
                if line.status_code == 404:
                    pass
                else:
                    if deviceNum == 1:
                        if sipPort == 'SIP_4_Port_MTA':
                            #origninal = r'config\orig_config\VEGA_4P_AV_DISABLED_USERS_TEMPLATE_CONFIG_SEP2022vF1.txt'
                            origninal = r'/home/pi/API-Webpage/venv/Build/config/orig_config/VEGA_4P_AV_DISABLED_USERS_TEMPLATE_CONFIG_SEP2022vF1.txt'
                        elif sipPort == 'SIP_8_Port_MTA':
                            #origninal = r'config\orig_config\NEW8Ptemplateconfig10122022F1.txt'
                            origninal = r'/home/pi/API-Webpage/venv/Build/config/orig_config/NEW8Ptemplateconfig10122022F1.txt'
                        elif sipPort == 'SIP_24_Port_MTA':
                            #origninal = r'config\orig_config\24PORT-VEGA3000G-config-10042022-DISABLED-USERS-AV-TEMPLATE.txt'
                            origninal = r'/home/pi/API-Webpage/venv/Build/config/orig_config/24PORT-VEGA3000G-config-10042022-DISABLED-USERS-AV-TEMPLATE.txt'
                    if deviceNum == 2:
                        if sipPort2 == 'SIP_4_Port_MTA':
                            #origninal = r'config\orig_config\VEGA_4P_AV_DISABLED_USERS_TEMPLATE_CONFIG_SEP2022vF1.txt'
                            origninal = r'/home/pi/API-Webpage/venv/Build/config/orig_config/VEGA_4P_AV_DISABLED_USERS_TEMPLATE_CONFIG_SEP2022vF1.txt'
                        elif sipPort2 == 'SIP_8_Port_MTA':
                            #origninal = r'config\orig_config\NEW8Ptemplateconfig10122022F1.txt'
                            origninal = r'/home/pi/API-Webpage/venv/Build/config/orig_config/NEW8Ptemplateconfig10122022F1.txt'
                        elif sipPort2 == 'SIP_24_Port_MTA':
                            #origninal = r'config\orig_config\24PORT-VEGA3000G-config-10042022-DISABLED-USERS-AV-TEMPLATE.txt'
                            origninal = r'/home/pi/API-Webpage/venv/Build/config/orig_config/24PORT-VEGA3000G-config-10042022-DISABLED-USERS-AV-TEMPLATE.txt'
                    if deviceNum == 1:
                        #newFileName = r'config\new_config\\' + mac[0].upper() + 'config.txt'
                        #newScriptFile = r'config\new_config\\' + mac[0].upper() + 'script.txt'
                        newFileName = r'/tftpboot/' + mac[0].upper() + 'config.txt'
                        newScriptFile = r'/tftpboot/' + mac[0].upper() + 'script.txt'
                    if deviceNum == 2:
                        #newFileName = r'config\new_config\\' + mac[1].upper() + 'config.txt'
                        #newScriptFile = r'config\new_config\\' + mac[1].upper() + 'script.txt'
                        newFileName = r'/tftpboot/' + mac[1].upper() + 'config.txt'
                        newScriptFile = r'/tftpboot/' + mac[1].upper() + 'script.txt'

                    if deviceNum == 1:
                        if sipPort == 'SIP_4_Port_MTA':
                            sipNum1 = 4
                        if sipPort == 'SIP_8_Port_MTA':
                            sipNum1 = 8
                        if sipPort == 'SIP_24_Port_MTA':
                            sipNum1 = 24

                    #baseScript = r'config\orig_script\baseConfigScript.txt'
                    baseScript = r'/home/pi/API-Webpage/venv/Build/config/orig_script/baseConfigScript.txt'

                    shutil.copyfile(origninal, newFileName)
                    shutil.copyfile(baseScript, newScriptFile)

                    if deviceNum == 1:
                        usernamesTMP = usernames[:sipNum1]
                    elif deviceNum == 2:
                        usernamesTMP = usernames[sipNum1:]
                    countUsr = len(usernamesTMP)
                    for user in usernamesTMP:
                        if user == '':
                            pass
                        else:
                            with open(newFileName, 'r') as file:
                                data = file.read()
                                if sipPort == 'SIP_24_Port_MTA' or sipPort == 'SIP_50_Port_ATA':
                                    if countUsr < 10:
                                        data = data.replace("SIP_USERNAME_LINE0" + str(countUsr), user)
                                        data = data.replace('.sip.reg.user.' + str(countUsr) + '.enable="0"',
                                                            '.sip.reg.user.' + str(countUsr) + '.enable="1"')
                                    else:
                                        data = data.replace("SIP_USERNAME_LINE" + str(countUsr), user)
                                        data = data.replace('.sip.reg.user.' + str(countUsr) + '.enable="0"',
                                                            '.sip.reg.user.' + str(countUsr) + '.enable="1"')
                                else:
                                    data = data.replace("SIP_USERNAME_LINE" + str(countUsr), user)
                                    data = data.replace('.sip.reg.user.' + str(countUsr) + '.enable="0"',
                                                        '.sip.reg.user.' + str(countUsr) + '.enable="1"')

                            with open(newFileName, 'w') as file:
                                file.write(data)
                            countUsr = countUsr - 1

                    if deviceNum == 1:
                        passwordsTMP = passwords[:sipNum1]
                    elif deviceNum == 2:
                        passwordsTMP = passwords[sipNum1:]
                    #print(deviceNum)
                    #print(passwordsTMP)
                    countPwd = len(passwordsTMP)
                    #print(countPwd)
                    for pwd in passwordsTMP:
                        with open(newFileName, 'r') as file:
                            data = file.read()
                            if sipPort == 'SIP_24_Port_MTA' or sipPort == 'SIP_50_Port_ATA':
                                if countPwd < 10:
                                    data = data.replace("SIP_PASSWORD_LINE0" + str(countPwd), pwd)
                                    data = data.replace('.sip.auth.user.' + str(countPwd) + '.enable="0"',
                                                        '.sip.auth.user.' + str(countPwd) + '.enable="1"')
                                else:
                                    data = data.replace("SIP_PASSWORD_LINE" + str(countPwd), pwd)
                                    data = data.replace('.sip.auth.user.' + str(countPwd) + '.enable="0"',
                                                        '.sip.auth.user.' + str(countPwd) + '.enable="1"')
                            else:
                                data = data.replace("SIP_PASSWORD_LINE" + str(countPwd), pwd)
                                data = data.replace('.sip.auth.user.' + str(countPwd) + '.enable="0"',
                                                    '.sip.auth.user.' + str(countPwd) + '.enable="1"')

                        with open(newFileName, 'w') as file:
                            file.write(data)
                        countPwd = countPwd - 1
                    logger.error("Created config file at " + str(newFileName))
                    if deviceNum == 1:
                        File1 = newFileName
                    elif deviceNum == 2:
                        File2 = newFileName
    ZipSent = mac[0]+'_'+mac[1]+'config.zip'
    with ZipFile(ZipSent, 'w') as zipObj:
        # Add multiple files to the zip
        zipObj.write(File1)
        zipObj.write(File2)
    return ZipSent



def config_template(Partitionid, Accountid, headers, usernames, passwords, sipPort, mac):
    for prt in Partitionid:
        for act in Accountid:
            line = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/" + act, headers=headers)
            l = json.loads(line.text)
            logger.error("Configure Template:" + str(l))
            # print("3:")
            # print(l)
            if line.status_code == 401:
                if l["messages"] == 'ExpiredAuthToken':
                    return redirect(url_for('logout'))
            if line.status_code == 404:
                pass
            else:
                if sipPort == 'SIP_4_Port_MTA':
                    #origninal = r'config\orig_config\VEGA_4P_AV_DISABLED_USERS_TEMPLATE_CONFIG_SEP2022vF1.txt'
                    origninal = r'/home/pi/API-Webpage/venv/Build/config/orig_config/VEGA_4P_AV_DISABLED_USERS_TEMPLATE_CONFIG_SEP2022vF1.txt'
                elif sipPort == 'SIP_8_Port_MTA':
                    #origninal = r'config\orig_config\NEW8Ptemplateconfig10122022F1.txt'
                    origninal = r'/home/pi/API-Webpage/venv/Build/config/orig_config/NEW8Ptemplateconfig10122022F1.txt'
                elif sipPort == 'SIP_24_Port_MTA':
                    #origninal = r'config\orig_config\24PORT-VEGA3000G-config-10042022-DISABLED-USERS-AV-TEMPLATE.txt'
                    origninal = r'/home/pi/API-Webpage/venv/Build/config/orig_config/24PORT-VEGA3000G-config-10042022-DISABLED-USERS-AV-TEMPLATE.txt'
                elif sipPort == 'SIP_50_Port_ATA':
                    #origninal = r'config\orig_config\VEGA3050G_Disabled_Users_12_06_2022.txt'
                    origninal = r'/home/pi/API-Webpage/venv/Build/config/orig_config/24PORT-VEGA3000G-config-10042022-DISABLED-USERS-AV-TEMPLATE.txt'

                #newFileName = r'config\new_config\\' + mac.upper() + 'config.txt'
                #newScriptFile = r'config\new_config\\' + mac.upper() + 'script.txt'
                newFileName = r'/tftpboot/' + mac.upper() + 'config.txt'
                newScriptFile = r'/tftpboot/' + mac.upper() + 'script.txt'

                #baseScript = r'config\orig_script\baseConfigScript.txt'
                baseScript = r'/home/pi/API-Webpage/venv/Build/config/orig_script/baseConfigScript.txt'

                shutil.copyfile(origninal, newFileName)
                shutil.copyfile(baseScript, newScriptFile)
                countUsr = len(usernames)
                for user in usernames:
                    if user == '':
                        pass
                    else:
                        with open(newFileName, 'r') as file:
                            data = file.read()
                            if sipPort == 'SIP_24_Port_MTA' or sipPort == 'SIP_50_Port_ATA':
                                if countUsr < 10:
                                    data = data.replace("SIP_USERNAME_LINE0" + str(countUsr), user)
                                    data = data.replace('.sip.reg.user.' + str(countUsr) + '.enable="0"',
                                                        '.sip.reg.user.' + str(countUsr) + '.enable="1"')
                                else:
                                    data = data.replace("SIP_USERNAME_LINE" + str(countUsr), user)
                                    data = data.replace('.sip.reg.user.' + str(countUsr) + '.enable="0"',
                                                        '.sip.reg.user.' + str(countUsr) + '.enable="1"')
                            else:
                                data = data.replace("SIP_USERNAME_LINE" + str(countUsr), user)
                                data = data.replace('.sip.reg.user.' + str(countUsr) + '.enable="0"',
                                                    '.sip.reg.user.' + str(countUsr) + '.enable="1"')

                        with open(newFileName, 'w') as file:
                            file.write(data)
                        countUsr = countUsr - 1

                countPwd = len(passwords)
                for pwd in passwords:
                    with open(newFileName, 'r') as file:
                        data = file.read()
                        if sipPort == 'SIP_24_Port_MTA' or sipPort == 'SIP_50_Port_ATA':
                            if countPwd < 10:
                                data = data.replace("SIP_PASSWORD_LINE0" + str(countPwd), pwd)
                                data = data.replace('.sip.auth.user.' + str(countPwd) + '.enable="0"',
                                                    '.sip.auth.user.' + str(countPwd) + '.enable="1"')
                            else:
                                data = data.replace("SIP_PASSWORD_LINE" + str(countPwd), pwd)
                                data = data.replace('.sip.auth.user.' + str(countPwd) + '.enable="0"',
                                                    '.sip.auth.user.' + str(countPwd) + '.enable="1"')
                        else:
                            data = data.replace("SIP_PASSWORD_LINE" + str(countPwd), pwd)
                            data = data.replace('.sip.auth.user.' + str(countPwd) + '.enable="0"',
                                                '.sip.auth.user.' + str(countPwd) + '.enable="1"')

                    with open(newFileName, 'w') as file:
                        file.write(data)
                    countPwd = countPwd - 1
                logger.error("Created config file at " + str(newFileName))
                return newFileName


def create_mult_device(Partitionid, Accountid, headers, mac, sipPort, sipPort2):
    usernames = []
    passwords = []
    error = []
    total = [1,2]
    mac = mac.replace(":", "")
    mac = mac.split(",")
    for prt in Partitionid:
        for act in Accountid:
            for deviceNum in total:
                #print("3:"+str(deviceNum))
                if deviceNum == 1:
                    if sipPort == 'SIP_4_Port_MTA':
                        sipNum1 = 4
                    if sipPort == 'SIP_8_Port_MTA':
                        sipNum1 = 8
                    if sipPort == 'SIP_24_Port_MTA':
                        sipNum1 = 24
                # get the user id
                userID = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/" + act + "/user",headers=headers)
                u = json.loads(userID.text)
                #print(userID)
                #print(userID.text)
                #print(u)
                logger.error("Configure Device Users:" + str(u))
                ifAccountinPartition = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/" + act,headers=headers)
                i = json.loads(ifAccountinPartition.text)
                logger.error("Check if account in partition:" + str(i))
                if ifAccountinPartition.status_code == 404:
                    pass
                else:
                    if u == []:
                        error.append("No Users on Account")
                for x in u:
                    callerID = x["callerIdConfig"]
                    cID = callerID["callerIdNumber"]
                    if cID == '':
                        error.append("Caller ID Not Assigned")
                if userID.status_code == 401:
                    if u["messages"] == 'ExpiredAuthToken':
                        return redirect(url_for('logout'))
                #print("1:")
                #print(u)
                #print(userID)
                #print(prt)
                if u == []:
                    pass
                else:
                    y = []
                    for x in u:
                        y.append(x["extension"])
                    y.sort()
                    if deviceNum == 1:
                        y = y[:sipNum1]
                    elif deviceNum == 2:
                        y = y[sipNum1:]
                    #print("4:"+str(y))
                    lineNum = 1
                    while len(y) != 0 and error == []:
                        for user in u:
                            if len(y) == 0:
                                pass
                            elif y[0] == user["extension"]:
                                endUser = user["id"]
                                #print(endUser)
                                #get users name
                                callerIdConfig = user["callerIdConfig"]
                                phoneNum = callerIdConfig["callerIdNumber"]
                                #print(phoneNum)
                                usernames.append(phoneNum)
                                #get phonenumber associated with user
                                deviceName = "Line "+str(lineNum)
                                #Line name
                                length = random.randint(10, 12)
                                letters = string.ascii_letters
                                num = string.digits
                                pwd = letters + num
                                sipPassword = ''.join(random.choice(pwd) for i in range(length))
                                passwords.append(sipPassword)
                                # generates password
                                if deviceNum == 1:
                                    mac2 = mac[0]
                                if deviceNum == 2:
                                    mac2 = mac[1]
                                #print("6:")
                                #print(mac2)
                                apiInfo.mac = mac
                                # filter mac address if it has ":"
                                if deviceNum == 1:
                                    Port = sipPort
                                elif deviceNum == 2:
                                    Port = sipPort2
                                #print(Port)
                                newDevicebody = {
                                          "id": "string",
                                          "deviceTypeId": Port,
                                          "accountId": act,
                                          "partitionId": prt,
                                          "macAddress": mac2,
                                          "deviceName": deviceName,
                                          "emergencyNumber": phoneNum,
                                          "emergencyNumberReservationId": None,
                                          "faxEnabled": False,
                                          "lineNumber": lineNum,
                                          "userId": endUser,
                                          "sipPassword": sipPassword,
                                          "sipUsername": phoneNum,
                                          "zipcode": "string",
                                          "state": "string",
                                          "lineType": "Line",
                                          "referenceId": None
                                        }
                                logger.error("New Device Body:" + str(newDevicebody))
                                newDevice = requests.post("https://api.alianza.com/v2/partition/"+prt+"/account/"+act+"/deviceline",headers=headers, json=newDevicebody)
                                n = json.loads(newDevice.text)
                                #print("7:")
                                #print(n)
                                logger.error("Create Device:" + str(n))
                                if newDevice.status_code == 401:
                                    if n["messages"] == 'ExpiredAuthToken':
                                        return redirect(url_for('logout'))
                                #print(n)
                                if newDevice.status_code == 400:
                                    if n['messages'] == ['InvalidMacAddress']:
                                        error.append("Invalid Mac Address")
                                        #print(error)
                                    elif n['messages'] == ['SipUsernameInUse']:
                                        error.append("Device has lines already or Multiple Users have same Caller-ID assigned")
                                        #print(error)
                                    elif n['messages'] == ['NotPermitted']:
                                        error.append("Incorrect Partition Login")
                                        return redirect(url_for('logout'))
                                    elif n['messages'] == ['InvalidLineNumber']:
                                        pass
                                    else:
                                        error.append(n['messages'])
                                else:
                                    lineNum = lineNum + 1
                                    y.remove(y[0])
    usernames.reverse()
    passwords.reverse()
    logger.error("New Device Credentials:" + str(usernames) + str(passwords))
    #print(usernames)
    #print(passwords)
    return(usernames,passwords,error)


def create_device(Partitionid, Accountid, headers, mac, sipPort):
    usernames = []
    passwords = []
    error = []
    for prt in Partitionid:
        for act in Accountid:
            # get the user id
            userID = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/" + act + "/user",
                                  headers=headers)
            u = json.loads(userID.text)
            # print(userID)
            # print(userID.text)
            # print(u)
            logger.error("Configure Device Users:" + str(u))
            ifAccountinPartition = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/" + act,
                                                headers=headers)
            i = json.loads(ifAccountinPartition.text)
            logger.error("Check if account in partition:" + str(i))
            if ifAccountinPartition.status_code == 404:
                pass
            else:
                if u == []:
                    error.append("No Users on Account")
            for x in u:
                callerID = x["callerIdConfig"]
                cID = callerID["callerIdNumber"]
                if cID == '':
                    error.append("Caller ID Not Assigned")
            if userID.status_code == 401:
                if u["messages"] == 'ExpiredAuthToken':
                    return redirect(url_for('logout'))
            # print("1:")
            # print(u)
            # print(userID)
            # print(prt)
            if u == []:
                pass
            else:
                y = []
                for x in u:
                    y.append(x["extension"])
                y.sort()
                # print(y)
                lineNum = 1
                while len(y) != 0 and error == []:
                    for user in u:
                        if len(y) == 0:
                            pass
                        elif user['firstName'] == 'Digital':
                            y.remove(y[0])
                        elif y[0] == user["extension"]:
                            endUser = user["id"]
                            # print(endUser)
                            # get users name
                            callerIdConfig = user["callerIdConfig"]
                            phoneNum = callerIdConfig["callerIdNumber"]
                            # print(phoneNum)
                            usernames.append(phoneNum)
                            # get phonenumber associated with user
                            deviceName = "Line " + str(lineNum)
                            # Line name
                            length = random.randint(10, 12)
                            letters = string.ascii_letters
                            num = string.digits
                            pwd = letters + num
                            sipPassword = ''.join(random.choice(pwd) for i in range(length))
                            passwords.append(sipPassword)
                            # generates password
                            mac = mac.replace(":", "")
                            apiInfo.mac = mac
                            # filter mac address if it has ":"
                            newDevicebody = {
                                "id": "string",
                                "deviceTypeId": sipPort,
                                "accountId": act,
                                "partitionId": prt,
                                "macAddress": mac,
                                "deviceName": deviceName,
                                "emergencyNumber": phoneNum,
                                "emergencyNumberReservationId": None,
                                "faxEnabled": False,
                                "lineNumber": lineNum,
                                "userId": endUser,
                                "sipPassword": sipPassword,
                                "sipUsername": phoneNum,
                                "zipcode": "string",
                                "state": "string",
                                "lineType": "Line",
                                "referenceId": None
                            }
                            logger.error("New Device Body:" + str(newDevicebody))
                            newDevice = requests.post(
                                "https://api.alianza.com/v2/partition/" + prt + "/account/" + act + "/deviceline",
                                headers=headers, json=newDevicebody)
                            # print("2:")
                            # print(newDevice)
                            n = json.loads(newDevice.text)
                            logger.error("Create Device:" + str(n))
                            if newDevice.status_code == 401:
                                if n["messages"] == 'ExpiredAuthToken':
                                    return redirect(url_for('logout'))
                            # print(n)
                            if newDevice.status_code == 400:
                                if n['messages'] == ['InvalidMacAddress']:
                                    error.append("Invalid Mac Address")
                                    # print(error)
                                elif n['messages'] == ['SipUsernameInUse']:
                                    error.append("Device has lines already")
                                    # print(error)
                                elif n['messages'] == ['NotPermitted']:
                                    return redirect(url_for('logout'))
                                elif n['messages'] == ['InvalidLineNumber']:
                                    error.append("Too Many Lines for Device Chosen")
                                else:
                                    error.append(n['messages'])
                            else:
                                lineNum = lineNum + 1
                                y.remove(y[0])
                usernames.reverse()
                passwords.reverse()
                # print(usernames)
                # print(passwords)
                logger.error("New Device Credentials:" + str(usernames) + str(passwords))
    return (usernames, passwords, error)


def sip_ports(port):
    error = []
    port = request.args.get('port')
    #print(port)
    if port == '4':
        sipPort = 'SIP_4_Port_MTA'
        apiInfo.sipPort = 'SIP_4_Port_MTA'
        sipPort2 = ''
        apiInfo.sipPort2 = ''
    elif port == '8':
        sipPort = 'SIP_8_Port_MTA'
        apiInfo.sipPort = 'SIP_8_Port_MTA'
        sipPort2 = ''
        apiInfo.sipPort2 = ''
    elif port == '24':
        sipPort = 'SIP_24_Port_MTA'
        apiInfo.sipPort = 'SIP_24_Port_MTA'
        sipPort2 = ''
    elif port == '50':
        sipPort = 'SIP_50_Port_ATA'
        apiInfo.sipPort = 'SIP_50_Port_ATA'
        sipPort2 = ''
        apiInfo.sipPort2 = ''
    elif port == '8,8':
        sipPort = 'SIP_8_Port_MTA'
        apiInfo.sipPort = 'SIP_8_Port_MTA'
        sipPort2 = 'SIP_8_Port_MTA'
        apiInfo.sipPort2 = 'SIP_8_Port_MTA'
    elif port == '8,4':
        sipPort = 'SIP_8_Port_MTA'
        apiInfo.sipPort = 'SIP_8_Port_MTA'
        sipPort2 = 'SIP_4_Port_MTA'
        apiInfo.sipPort2 = 'SIP_4_Port_MTA'
    elif port == '4,8':
        sipPort = 'SIP_4_Port_MTA'
        apiInfo.sipPort = 'SIP_4_Port_MTA'
        sipPort2 = 'SIP_8_Port_MTA'
        apiInfo.sipPort2 = 'SIP_8_Port_MTA'
    elif port == '4,4':
        sipPort = 'SIP_4_Port_MTA'
        apiInfo.sipPort = 'SIP_4_Port_MTA'
        sipPort2 = 'SIP_4_Port_MTA'
        apiInfo.sipPort2 = 'SIP_4_Port_MTA'
    else:
        sipPort = ''
        sipPort2 = ''
        error.append('Invalid SIP Port')
    #print(sipPort)
    #print(sipPort2)
    return (sipPort, error, sipPort2)


def search_account(Partitionid, headers, error, Accountid):
    for prt in Partitionid:
        apiInfo.Accountid = []
        apiInfo.accountName = []
        q = request.args.get('q')
        search = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/search?q=" + q, headers=headers)
        actInfo = json.loads(search.text)
        logger.error("Default search:" + str(actInfo))
        if search.status_code == 401:
            if actInfo["messages"] == 'ExpiredAuthToken':
                return redirect(url_for('logout'))
        # print(actInfo)
        for x in actInfo:
            # Accountid = {"faDoXhjKSJmj3-wwcmQfdA"}             # av technology
            # Accountid = {"oBZQIW-QTQibUi-5ZtEV7A"}             #092821
            # Accountid = {"mQVH7PgdTiGc-nycT2efNQ"}             #curia alexander
            apiInfo.Accountid.append(x["id"])
            Accountid = apiInfo.Accountid
            # print(x['accountNumber'])
            apiInfo.accountName.append(x['accountNumber'])
        # print(Accountid)
        if len(Accountid) > 1:
            error.append('Please be more specific in search')
        elif len(Accountid) == 0:
            error.append('Cannot find account')
        q = None
        return (error, q, Accountid)


@app.route("/adduser", methods=['GET', 'POST'])
def adduser():
    firstname = ""
    lastname = ""
    extension = ""
    headers = apiInfo.headers
    Partitionid = apiInfo.Partitionid
    step = 1
    error = []
    Accountid = []

    if len(Accountid) != 1:
        step = 1
        q = request.args.get('q')
        if q != None:
            apiInfo.Accountid = []
            while len(apiInfo.Accountid) != 1:
                error, q, Accountid = search_account(Partitionid, headers, error, Accountid)
                if len(apiInfo.Accountid) == 1:
                    step = 2
                return render_template('adduser.html', error=error, step=step, accountName=apiInfo.accountName)

    if len(apiInfo.Accountid) == 1 and error == []:
        step = 2
        fname = request.args.get('firstname')
        if fname != None:
            apiInfo.firstname = ''
            firstname = fname
            apiInfo.firstname = firstname
            if firstname != '':
                step = 3
            return render_template('adduser.html',error=error, step=step, firstname=firstname,accountName=apiInfo.accountName)

    if apiInfo.firstname != '' and error == []:
        step = 3
        lname = request.args.get('lastname')
        if lname != None:
            apiInfo.lastname = ''
            lastname = lname
            apiInfo.lastname = lastname
            if lastname != '':
                step = 4
            return render_template('adduser.html',error=error, step=step, firstname=apiInfo.firstname,lastname=lastname,accountName=apiInfo.accountName)

    if apiInfo.lastname != '' and error == []:
        step = 4
        ext = request.args.get('extension')
        if ext != None:
            extension = ext
            for prt in Partitionid:
                for act in apiInfo.Accountid:
                    num = randint(100, 999)
                    username = apiInfo.firstname+"line"+str(num)
                    email = apiInfo.firstname+str(num)+"line@example.com"
                    user = {
                          "id": None,
                          "username": username,
                          "password": "",
                          "firstName": apiInfo.firstname,
                          "lastName": apiInfo.lastname,
                          "emailAddress": email,
                          "mustChangePassword": True,
                          "languageTag": "en-US",
                          "partitionId": prt,
                          "accountId": act,
                          "callingPlans": [
                            {
                              "id": None,
                              "referenceId": "P03NyYtKRkKfjXiGgV9PDg",
                              "referenceType": "END_USER",
                              "callingPlanProductId": "tBvYnyK_T1G0-JoDKb5nWg",
                              #"endDate": "2022-08-16T12:21:55.809Z",
                              #"startDate": "2022-08-16T12:21:55.810Z",
                              "planMinutes": 10000,
                              "secondsRemaining": 600000
                            }
                          ],
                          "timeZone": "US/Eastern",
                          "extension": ext,
                          "callerIdConfig": {
                            "callerIdNumber": "",
                            "externalCallerIdVisible": True,
                            "extensionCallerIdVisible": True,
                          },
                          "callHandlingSettings": {
                            "callWaitingEnabled": True,
                            "doNotDisturbEnabled": True,
                            "callHandlingOptionType": "RingPhone",
                            "forwardAlwaysToNumber": "string",
                            "ringPhoneCallHandling": {
                              "busyCallHandling": {
                                "type": "Voicemail",
                                "forwardToNumber": ""
                              },
                              "noAnswerCallHandling": {
                                "type": "Voicemail",
                                "timeout": 20,
                                "forwardToNumber": ""
                              },
                              "unregisteredCallHandling": {
                                "type": "Voicemail",
                                "forwardToNumber": ""
                              }
                            },
                            "simultaneousRingCallHandling": {
                              "forwardToNumberList": [
                                ""
                              ],
                              "noAnswerCallHandling": {
                                "type": "Voicemail",
                                "timeout": 20,
                                "forwardToNumber": ""
                              }
                            },
                          },
                          "callScreeningSettings": {
                            "anonymousCallScreen": "Allow",
                            "anonymousRingType": "StandardRing",
                            "tollFreeCallScreen": "Allow",
                            "tollFreeRingType": "StandardRing",
                            "defaultCallScreen": "Allow",
                            "defaultRingType": "StandardRing",
                            "customCallScreenList": [
                            ],
                            "forwardTn": ""
                          },
                          "voicemailBoxId": None,
                          "endUserType": "STANDARD",
                          "userProductPlan": "STANDARD",
                          "pinLockedOut": False,
                          #"welcomeEmailSent": "2022-08-16T12:21:55.811Z",
                          "allowPortalAccess": True
                        }
                    create = requests.post("https://api.alianza.com/v2/partition/"+prt+"/account/"+act+"/user", headers=headers,json=user)
                    x = json.loads(create.text)
                    logger.error("New Account:" + str(x))
                    if create.status_code == 400:
                        error.append(x['messages'])
                    step = 1
            return render_template('adduser.html', error=error, step=step, firstname=firstname,accountName=apiInfo.accountName)
    return render_template('adduser.html', error=error, step=step, firstname=firstname,accountName=apiInfo.accountName)



@app.route("/addaccount", methods=['GET', 'POST'])
def addaccount():
    headers = apiInfo.headers
    step = 1
    error = []
    prt = []
    prtName = ''
    actNum = ''
    actName = ''

    #Choose which partition
    #print("1: ")
    #print(prt)
    if len(prt) != 1:
        step = 1
        x = request.args.get('q')
        #print("6:")
        #print(x)
        if x != None:
            #print("7")
            #while len(apiInfo.prt) != 1:
            if x == 'WF':
                apiInfo.prt = []
                prt.append('Q8MUf4fWRkuckIhWMcUg1w')
                apiInfo.prt = prt
                prtName = x
                if apiInfo.prt != []:
                    step = 2
                return render_template('addaccount.html',error=error, step=step, q=prtName)
            elif x == "Lumen":
                prt.append('kT8A3FFXSQuWCbxs58Iiug')
                prtName = x
                if apiInfo.prt != []:
                    step = 2
                #print("4: "+prtName)
                return render_template('addaccount.html',error=error, step=step, q=prtName)
            else:
                error.append("Invalid Partition")

    #print("2: ")
    #print(apiInfo.prt)
    if len(apiInfo.prt) == 1 and error == []:
        step = 2
        #print("5:")
        an = request.args.get('actName')
        if an != None:
            apiInfo.actName = []
            actName = an
            apiInfo.actName = actName
            if actName != '':
                step = 3
            return render_template('addaccount.html',error=error, step=step, actName=actName,q=prtName)

    print("3: ")
    print(apiInfo.actName)
    if apiInfo.actName != [] and error == []:
        step = 3
        am = request.args.get('actNum')
        if am != None:
            for prt in apiInfo.prt:
                actNum = am
                #print("8: ")
                #print(actNum)
                #step = 4
                account = {
                    "id": "string",
                    "partitionId": "string",
                    "accountNumber": actNum,
                    "accountName": apiInfo.actName,
                    "billingCycleDay": 1,
                    "status": "ACTIVE",
                    "timeZone": "US/Eastern",
                    "accountType": "ADVANCED",
                    "platformType": "CPE2",
                    "inboundRatePlanProductId": None,
                    "extensionLength": 4,
                    "dialingBehaviorType": "TEN_DIGIT",
                    "regulatoryType": "RESIDENTIAL",
                }
                create = requests.post("https://api.alianza.com/v2/partition/" + prt + "/account", headers=headers,
                                       json=account)
                x = json.loads(create.text)
                logger.error("New Account:" + str(x))
                if create.status_code == 400:
                    error.append(x['messages'])
                step = 1
                return render_template('addaccount.html',error=error, step=step, actName=actName, actNum=actNum,q=prtName)
    return render_template('addaccount.html', error=error, step=step, actName=actName, actNum=actNum, q=prtName)


@app.route("/adddevice", methods=['GET', 'POST'])
def adddevice():
    headers = apiInfo.headers
    Partitionid = apiInfo.Partitionid
    Accountid = []
    error = []
    sipPort = ''
    step = 1

    if len(Accountid) != 1:
        step = 1
        q = request.args.get('q')
        if q != None:
            apiInfo.Accountid = []
            while len(apiInfo.Accountid) != 1:
                error, q, Accountid = search_account(Partitionid, headers, error, Accountid)
                if len(apiInfo.Accountid) == 1:
                    step = 2
                return render_template('adddevice.html', error=error, step=step, accountName=apiInfo.accountName,
                                       sipPort=apiInfo.sipPort)

    if len(apiInfo.Accountid) == 1 and error == []:
        step = 2
        sipPort = ''
        sipPort2 = ''
        port = request.args.get('port')
        #print(port)
        if port != None:
            while sipPort == '':
                sipPort, error, sipPort2 = sip_ports(port)
                #print("1:"+sipPort2)
                if sipPort != '':
                    step = 3
                return render_template('adddevice.html', error=error, step=step, accountName=apiInfo.accountName,sipPort=apiInfo.sipPort, sipPort2=apiInfo.sipPort2)

    if apiInfo.sipPort != '' and error == []:
        step = 3
        usernames = []
        newFileName = ''
        mac = request.args.get('mac')
        # print(mac)
        # mac = "1050583033c3"                               #4 port
        if mac != None:
            while newFileName == '':
                #print("2:"+apiInfo.sipPort2)
                if apiInfo.sipPort2 == '':
                    usernames, passwords, error = create_device(apiInfo.Partitionid, apiInfo.Accountid, apiInfo.headers,mac, apiInfo.sipPort)
                else:
                    usernames, passwords, error = create_mult_device(apiInfo.Partitionid, apiInfo.Accountid,apiInfo.headers, mac, apiInfo.sipPort,apiInfo.sipPort2)
                if error != []:
                    pass
                else:
                    if apiInfo.sipPort2 == '':
                        newFileName = config_template(apiInfo.Partitionid, apiInfo.Accountid, apiInfo.headers, usernames,passwords, apiInfo.sipPort, apiInfo.mac)
                        step = 1
                    else:
                        newFileName = mult_config_template(apiInfo.Partitionid, apiInfo.Accountid, apiInfo.headers,usernames, passwords, apiInfo.sipPort, apiInfo.mac,apiInfo.sipPort2)
                        step = 1
                    return send_file(newFileName, as_attachment=True)
                if newFileName != '':
                    step = 1
                return render_template('adddevice.html', error=error, step=step, accountName=apiInfo.accountName,sipPort=apiInfo.sipPort, newFileName=newFileName)

    step = 1
    apiInfo.Accountid = []
    apiInfo.sipPort = ''
    apiInfo.sipPort2 = ''

    return render_template('adddevice.html', error=error, step=step, accountName=apiInfo.accountName,
                           sipPort=apiInfo.sipPort)

@app.route("/callhistory", methods=['GET', 'POST'])
def callhistory():
    countA = 1
    headers = apiInfo.headers
    Partitionid = apiInfo.Partitionid
    Accountid = []
    partitionName = []
    accountName = []
    actID = []
    actNum = 0

    origNumber = []
    termNumber = []
    startTime = []
    actualCallLengthSeconds = []
    totalRecords = []

    render_template('callhistory.html', totAct=len(accountName))
    q = request.args.get('q')
    # print(q)
    if q != None:
        for prt in Partitionid:
            if len(Accountid) != 0:
                countA = 1
                headers = apiInfo.headers
                Partitionid = apiInfo.Partitionid
                Accountid = []
                partitionName = []
                accountName = []

                origNumber = []
                termNumber = []
                startTime = []
                actualCallLengthSeconds = []
                totalRecords = []

                actID = []
                actNum = 0
            while len(Accountid) == 0:

                # q = input("What Account are you looking for\n")

                search = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/search?q=" + q,
                                      headers=headers)
                actInfo = json.loads(search.text)
                logger.error("Call History Search:" + str(actInfo))
                if search.status_code == 401:
                    if actInfo["messages"] == 'ExpiredAuthToken':
                        return redirect(url_for('logout'))

                # print(actInfo)

                for x in actInfo:
                    # print(x["id"])
                    Accountid.append(x["id"])
                    # print(x['accountNumber'])
                    # print(x['accountName'])
                    # print('')
                # print(Accountid)
                if len(Accountid) == 0:
                    accountName.append("Not Found")
                    Accountid.append("Not Found")

        endDate = datetime.now()
        endDatestr = endDate.strftime("%Y-%m-%d")
        startDate = date.today() - timedelta(days=10)
        startDatestr = startDate.strftime("%Y-%m-%d")
        # print(endDatestr)
        # print(startDatestr)
        for prt in Partitionid:
            partition = requests.get("https://api.alianza.com/v2/partition/" + prt, headers=headers)
            p = json.loads(partition.text)
            logger.error("Call History Partition Name:" + str(p))
            if partition.status_code == 401:
                if p["messages"] == 'ExpiredAuthToken':
                    return redirect(url_for('logout'))
            # print("Partition: " + p["name"])
            for act in Accountid:
                account = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/" + act,
                                       headers=headers)
                a = json.loads(account.text)
                logger.error("Call History Account Name:" + str(a))
                if account.status_code == 401:
                    if a["messages"] == 'ExpiredAuthToken':
                        return redirect(url_for('logout'))
                if account.status_code == 404:
                    pass
                else:
                    accountName.append(a["accountName"])
                    actNum = actNum + 1
                    history = requests.get(
                        "https://api.alianza.com/v2/partition/" + prt + "/account/" + act + "/cdrsearch?startDate=" + startDatestr + "&endDate=" + endDatestr + "&maxResult=10&sort=DATE&sortOrder=DESC",
                        headers=headers)
                    h = json.loads(history.text)
                    logger.error("Call History:" + str(h))
                    if history.status_code == 401:
                        if h["messages"] == 'ExpiredAuthToken':
                            return redirect(url_for('logout'))
                    # print(h)
                    totalRecords.append(h["totalRecords"])
                    if h["totalRecords"] == 0:
                        origNumber.append("None")
                        termNumber.append("None")
                        startTime.append("None")
                        actualCallLengthSeconds.append("None")
                        actID.append(actNum)
                    else:
                        for call in h["results"]:
                            # print("Call from ")
                            # print(call["origNumber"])
                            origNumber.append(call["origNumber"])
                            # print("to")
                            # print(call["termNumber"])
                            termNumber.append(call["termNumber"])
                            # print("at")
                            # print(call["startTime"])
                            startTime.append(call["startTime"])
                            # print("Length:")
                            # print(call["actualCallLengthSeconds"])
                            actualCallLengthSeconds.append(call["actualCallLengthSeconds"])
                            # print("")
                            actID.append(actNum)
                        # print("Total in last 10 days:")
                        # print(h["totalRecords"])
                        # print("")
                        # redirect(url_for('callhistory'))
    # print(origNumber,termNumber,startTime,actualCallLengthSeconds,totalRecords,accountName,actID,len(accountName),len(origNumber))
    return render_template('callhistory.html', origNumber=origNumber, termNumber=termNumber, startTime=startTime,
                           actualCallLengthSeconds=actualCallLengthSeconds, totalRecords=totalRecords,
                           totAct=len(accountName), len=len(origNumber), actID=actID, accountName=accountName)


@app.route("/registrationstatus", methods=['GET', 'POST'])
def registered():
    countA = 1
    headers = apiInfo.headers
    Partitionid = apiInfo.Partitionid
    Accountid = []
    partitionName = []
    accountName = []
    lineName = []
    Phonenumber = []
    regStatus = []
    actID = []
    actNum = 0

    render_template('registered.html', totAct=len(accountName))
    q = request.args.get('q')
    # print(q)
    if q != None:
        for prt in Partitionid:
            if len(apiInfo.Accountid) != 0:
                countA = 1
                headers = apiInfo.headers
                Partitionid = apiInfo.Partitionid
                Accountid = []
                partitionName = []
                accountName = []
                lineName = []
                Phonenumber = []
                regStatus = []
                actID = []
                actNum = 0
            while len(Accountid) == 0:

                # q = input("What Account are you looking for\n")

                search = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/search?q=" + q,
                                      headers=headers)
                # print(search)
                actInfo = json.loads(search.text)
                logger.error("Registered Account Search:" + str(actInfo))
                if search.status_code == 401:
                    if actInfo["messages"] == 'ExpiredAuthToken':
                        return redirect(url_for('logout'))
                # print(actInfo)

                for x in actInfo:
                    # print(x["id"])
                    Accountid.append(x["id"])
                    # print(x['accountNumber'])
                    # print(x['accountName'])
                    # print('')
                # print(Accountid)
                if len(Accountid) == 0:
                    accountName.append("Not Found")
                    Accountid.append("Not Found")

        for prt in Partitionid:
            partition = requests.get("https://api.alianza.com/v2/partition/" + prt, headers=headers)
            p = json.loads(partition.text)
            logger.error("Registered Partition Name:" + str(p))
            if partition.status_code == 401:
                if p["messages"] == 'ExpiredAuthToken':
                    return redirect(url_for('logout'))
            partitionName.append(p["name"])
            for act in Accountid:
                account = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/" + act,
                                       headers=headers)
                a = json.loads(account.text)
                logger.error("Registered Account Name:" + str(a))
                if account.status_code == 401:
                    if a["messages"] == 'ExpiredAuthToken':
                        return redirect(url_for('logout'))
                # print(a)
                if account.status_code == 404:
                    pass
                else:
                    accountName.append(a["accountName"])
                    BusinessLines = requests.get(
                        "https://api.alianza.com/v2/partition/" + prt + "/account/" + act + "/deviceline",
                        headers=headers)
                    y = json.loads(BusinessLines.text)
                    logger.error("Device Lines:" + str(y))
                    if BusinessLines.status_code == 401:
                        if y["messages"] == 'ExpiredAuthToken':
                            return redirect(url_for('logout'))
                    actNum = actNum + 1
                    for line in y:
                        # print(line)
                        lineName.append(line["deviceName"])  # Line name
                        Phonenumber.append(line["sipUsername"])  # Phonenumber
                        ids = line["id"]
                        registered = requests.get(
                            "https://api.alianza.com/v2/partition/" + prt + "/account/" + act + "/deviceline/" + ids + "/registrationstatus",
                            headers=headers)
                        z = json.loads(registered.text)
                        logger.error("Line is Registered:" + str(z))
                        if registered.status_code == 401:
                            if z["messages"] == 'ExpiredAuthToken':
                                return redirect(url_for('logout'))
                        # True/False if line is registered
                        if z["registered"] == True:
                            regStatus.append("Registered")
                        else:
                            regStatus.append("Not Registered")
                        # address = requests.get()
                        actID.append(actNum)
                        redirect(url_for('registered'))
    # print(accountName)
    # print([partitionName,accountName,len(lineName),lineName,Phonenumber, regStatus, actID])
    return render_template('registered.html', partitionName=partitionName, accountName=accountName, len=len(lineName),
                           totAct=len(accountName), lineName=lineName, Phonenumber=Phonenumber, regStatus=regStatus,
                           actID=actID)


@app.route('/logs', methods=['GET', 'POST'])
def logs():
    logger.error("Download Log")
    return send_file(r'home/pi/API-Webpage/venv/Build/Logs/Process.log', as_attachment=True)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logger.error("Logout:" + apiInfo.headers['X-AUTH-TOKEN'])
    apiInfo.headers['X-AUTH-TOKEN'] = ''
    return redirect(url_for('login'))


# Route for handling the login page logic
@app.route('/', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        query = {"username": request.form['username'], "password": request.form['password']}
        response = requests.post("https://api.alianza.com/v2/authorize", json=query)
        x = json.loads(response.text)
        logger.error("Login:" + str(x))
        if response.status_code == 201:
            apiInfo.headers['X-AUTH-TOKEN'] = x["authToken"]
            return redirect(url_for('registered'))
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)


@app.route("/<name>")
def hello(name):
    return f"{escape(name)}, Incorrect URL"


if __name__ == "__main__":
    # app.debug = True
    app.run(host="0.0.0.0", port=80)
    #app.run()
