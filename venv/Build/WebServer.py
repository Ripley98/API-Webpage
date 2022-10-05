from markupsafe import escape
from flask import Flask, render_template, redirect, url_for, request, session, send_file
from datetime import timedelta, date, datetime
import requests
import json
import random
import string
import shutil
import logging

app = Flask(__name__)

logging.basicConfig(filename="Logs/ProcessLog", level=logging.DEBUG,format="%(asctime)s %(message)s")

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
    mac = ''


def config_template(Partitionid, Accountid, headers, usernames, passwords, sipPort, mac):
    for prt in Partitionid:
        for act in Accountid:
            line = requests.get("https://api.alianza.com/v2/partition/"+prt+"/account/"+act,headers=headers)
            l = json.loads(line.text)
            logging.debug("Configure Template:" + str(l))
            #print("3:")
            #print(l)
            if line.status_code == 401:
                if l["message"] == 'Unauthorized' or l["messages"] == 'ExpiredAuthToken':
                    return redirect(url_for('logout'))
            if line.status_code == 404:
                pass
            else:
                if sipPort == 'SIP_4_Port_MTA':
                    origninal = r'config\orig_config\VEGA_4P_AV_DISABLED_USERS_TEMPLATE_CONFIG_SEP2022vF1.txt'
                elif sipPort == 'SIP_8_Port_MTA':
                    origninal = r'config\orig_config\VEGA_8P_AV_DISABLED_USERS_TEMPLATE_CONFIG_OCT2022vF1.txt'
                elif sipPort == 'SIP_24_Port_MTA':
                    origninal = r'config\orig_config\24PORT-VEGA3000G-config-10042022-DISABLED-USERS-AV-TEMPLATE.txt'

                newFileName = r'C:\Users\Public\Documents\FTP\\' +mac.upper()+ 'config.txt'
                newScriptFile= r'C:\Users\Public\Documents\FTP\\'+mac.upper()+ 'script.txt'

                baseScript = r'/config/orig_script/baseConfigScript.txt'

                shutil.copyfile(origninal,newFileName)
                shutil.copyfile(baseScript, newScriptFile)
                countUsr = len(usernames)
                for user in usernames:
                    if user == '':
                        pass
                    else:
                        with open(newFileName, 'r') as file:
                            data = file.read()
                            if sipPort == 'SIP_24_Port_MTA':
                                if countUsr < 10:
                                    data = data.replace("SIP_USERNAME_LINE0"+str(countUsr), user)
                                    data = data.replace('.sip.reg.user.' + str(countUsr) + '.enable="0"','.sip.reg.user.' + str(countUsr) + '.enable="1"')
                                else:
                                    data = data.replace("SIP_USERNAME_LINE" + str(countUsr), user)
                                    data = data.replace('.sip.reg.user.' + str(countUsr) + '.enable="0"','.sip.reg.user.' + str(countUsr) + '.enable="1"')
                            else:
                                data = data.replace("SIP_USERNAME_LINE" + str(countUsr), user)
                                data = data.replace('.sip.reg.user.' + str(countUsr) + '.enable="0"','.sip.reg.user.' + str(countUsr) + '.enable="1"')


                        with open(newFileName, 'w') as file:
                            file.write(data)
                        countUsr = countUsr - 1

                countPwd = len(passwords)
                for pwd in passwords:
                    with open(newFileName, 'r') as file:
                        data = file.read()
                        if sipPort == 'SIP_24_Port_MTA':
                            if countPwd < 10:
                                data = data.replace("SIP_PASSWORD_LINE0" + str(countPwd), pwd)
                                data = data.replace('.sip.auth.user.' + str(countPwd) + '.enable="0"','.sip.auth.user.' + str(countPwd) + '.enable="1"')
                            else:
                                data = data.replace("SIP_PASSWORD_LINE" + str(countPwd), pwd)
                                data = data.replace('.sip.auth.user.' + str(countPwd) + '.enable="0"','.sip.auth.user.' + str(countPwd) + '.enable="1"')
                        else:
                            data = data.replace("SIP_PASSWORD_LINE" + str(countPwd), pwd)
                            data = data.replace('.sip.auth.user.'+str(countPwd)+'.enable="0"','.sip.auth.user.'+str(countPwd)+'.enable="1"')

                    with open(newFileName, 'w') as file:
                        file.write(data)
                    countPwd = countPwd - 1
                logging.debug("Created config file at "+str(newFileName))
                return newFileName


def create_device(Partitionid, Accountid, headers, mac, sipPort):
    usernames = []
    passwords = []
    error = []
    for prt in Partitionid:
        for act in Accountid:
            # get the user id
            userID = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/" + act + "/user",headers=headers)
            u = json.loads(userID.text)
            #print(userID)
            #print(userID.text)
            #print(u)
            logging.debug("Configure Device Users:" + str(u))
            if u == []:
                error.append("No Users on Account")
            for x in u:
                callerID = x["callerIdConfig"]
                cID = callerID["callerIdNumber"]
                if cID == '':
                    error.append("Caller ID Not Assigned")
            if userID.status_code == 401:
                if u["message"] == 'Unauthorized' or u["messages"] == 'ExpiredAuthToken':
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
                #print(y)
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
                            mac=mac.replace(":","")
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
                            logging.debug("New Device Body:" + str(newDevicebody))
                            newDevice = requests.post("https://api.alianza.com/v2/partition/"+prt+"/account/"+act+"/deviceline",headers=headers, json=newDevicebody)
                            #print("2:")
                            #print(newDevice)
                            n = json.loads(newDevice.text)
                            logging.debug("Create Device:" + str(n))
                            if newDevice.status_code == 401:
                                if n["message"] == 'Unauthorized' or n["messages"] == 'ExpiredAuthToken':
                                    return redirect(url_for('logout'))
                            #print(n)
                            if newDevice.status_code == 400:
                                if n['messages'] == ['InvalidMacAddress']:
                                    error.append("Invalid Mac Address")
                                    #print(error)
                                elif n['messages'] == ['SipUsernameInUse']:
                                    error.append("Device has lines already")
                                    #print(error)
                                else:
                                    error.append(n['messages'])
                            else:
                                lineNum = lineNum + 1
                                y.remove(y[0])
                usernames.reverse()
                passwords.reverse()
                #print(usernames)
                #print(passwords)
                logging.debug("New Device Credentials:" + str(usernames) + str(passwords))
            return(usernames,passwords,error)


def sip_ports(port):
    error = []
    port = request.args.get('port')
    #print(port)
    if port == '2':
        sipPort = 'SIP_2_Port_MTA'
        apiInfo.sipPort = 'SIP_2_Port_MTA'
    elif port == '4':
        sipPort = 'SIP_4_Port_MTA'
        apiInfo.sipPort = 'SIP_4_Port_MTA'
    elif port == '8':
        sipPort = 'SIP_8_Port_MTA'
        apiInfo.sipPort = 'SIP_8_Port_MTA'
    elif port == '24':
        sipPort = 'SIP_24_Port_MTA'
        apiInfo.sipPort = 'SIP_24_Port_MTA'

    else:
        sipPort = ''
        error.append('Invalid SIP Port')
    return (sipPort, error)


def search_account(Partitionid,headers,error,Accountid):
    for prt in Partitionid:
        apiInfo.Accountid = []
        apiInfo.accountName = []
        q = request.args.get('q')
        search = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/search?q=" + q,headers=headers)
        actInfo = json.loads(search.text)
        logging.debug("Default search:" + str(actInfo))
        if search.status_code == 401:
            if actInfo["message"] == 'Unauthorized' or actInfo["messages"] == 'ExpiredAuthToken':
                return redirect(url_for('logout'))
        #print(actInfo)
        for x in actInfo:
            # Accountid = {"faDoXhjKSJmj3-wwcmQfdA"}             # av technology
            # Accountid = {"oBZQIW-QTQibUi-5ZtEV7A"}             #092821
            # Accountid = {"mQVH7PgdTiGc-nycT2efNQ"}             #curia alexander
            apiInfo.Accountid.append(x["id"])
            Accountid = apiInfo.Accountid
            #print(x['accountNumber'])
            apiInfo.accountName.append(x['accountNumber'])
        #print(Accountid)
        if len(Accountid) > 1:
            error.append('Please be more specific in search')
        elif len(Accountid) == 0:
            error.append('Cannot find account')
        q = None
        return (error, q, Accountid)





@app.route("/adddevice", methods=['GET','POST'])
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
                return render_template('adddevice.html', error=error,step=step,accountName=apiInfo.accountName,sipPort=apiInfo.sipPort)

    if len(apiInfo.Accountid) == 1 and error == []:
        step = 2
        sipPort = ''
        port = request.args.get('port')
        if port != None:
            while sipPort == '':
                sipPort, error = sip_ports(port)
                #print(sipPort)
                if sipPort != '':
                    step = 3
                return render_template('adddevice.html', error=error,step=step,accountName=apiInfo.accountName,sipPort=apiInfo.sipPort)

    if apiInfo.sipPort != '' and error == []:
        step = 3
        usernames = []
        newFileName = ''
        mac = request.args.get('mac')
        #print(mac)
        # mac = "1050583033c3"                               #4 port
        if mac != None:
            while newFileName == '':
                usernames, passwords, error = create_device(apiInfo.Partitionid, apiInfo.Accountid, apiInfo.headers, mac, apiInfo.sipPort)
                if error != []:
                    pass
                else:
                    newFileName = config_template(apiInfo.Partitionid, apiInfo.Accountid, apiInfo.headers, usernames, passwords, apiInfo.sipPort, apiInfo.mac)
                    step = 4
                    return send_file(newFileName, as_attachment=True)
                if newFileName != '':
                    step = 4
                return render_template('adddevice.html', error=error,step=step,accountName=apiInfo.accountName,sipPort=apiInfo.sipPort, newFileName=newFileName)

    step = 1
    apiInfo.Accountid = []
    apiInfo.sipPort = ''
        
    return render_template('adddevice.html',error=error,step=step,accountName=apiInfo.accountName,sipPort=apiInfo.sipPort)


@app.route("/callhistory", methods=['GET','POST'])
def callhistory():
    countA = 1
    headers= apiInfo.headers
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
    #print(q)
    if q!= None:
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

                #q = input("What Account are you looking for\n")

                search = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/search?q=" + q,
                                      headers=headers)
                actInfo = json.loads(search.text)
                logging.debug("Call History Search:" + str(actInfo))
                if search.status_code == 401:
                    if actInfo["message"] == 'Unauthorized' or actInfo["messages"] == 'ExpiredAuthToken':
                        return redirect(url_for('logout'))

                #print(actInfo)

                for x in actInfo:
                    #print(x["id"])
                    Accountid.append(x["id"])
                    #print(x['accountNumber'])
                    #print(x['accountName'])
                    #print('')
                #print(Accountid)
                if len(Accountid) == 0:
                    accountName.append("Not Found")
                    Accountid.append("Not Found")


        endDate = datetime.now()
        endDatestr = endDate.strftime("%Y-%m-%d")
        startDate = date.today() - timedelta(days=10)
        startDatestr = startDate.strftime("%Y-%m-%d")
        #print(endDatestr)
        #print(startDatestr)
        for prt in Partitionid:
            partition = requests.get("https://api.alianza.com/v2/partition/" + prt, headers=headers)
            p = json.loads(partition.text)
            logging.debug("Call History Partition Name:" + str(p))
            if partition.status_code == 401:
                if p["message"] == 'Unauthorized' or p["messages"] == 'ExpiredAuthToken':
                    return redirect(url_for('logout'))
            #print("Partition: " + p["name"])
            for act in Accountid:
                account = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/" + act, headers=headers)
                a = json.loads(account.text)
                logging.debug("Call History Account Name:" + str(a))
                if account.status_code == 401:
                    if a["message"] == 'Unauthorized' or a["messages"] == 'ExpiredAuthToken':
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
                    logging.debug("Call History:" + str(h))
                    if history.status_code == 401:
                        if h["message"] == 'Unauthorized' or h["messages"] == 'ExpiredAuthToken':
                            return redirect(url_for('logout'))
                    #print(h)
                    totalRecords.append(h["totalRecords"])
                    if h["totalRecords"] == 0:
                        origNumber.append("None")
                        termNumber.append("None")
                        startTime.append("None")
                        actualCallLengthSeconds.append("None")
                        actID.append(actNum)
                    else:
                        for call in h["results"]:
                            #print("Call from ")
                            #print(call["origNumber"])
                            origNumber.append(call["origNumber"])
                            #print("to")
                            #print(call["termNumber"])
                            termNumber.append(call["termNumber"])
                            #print("at")
                            #print(call["startTime"])
                            startTime.append(call["startTime"])
                            #print("Length:")
                            #print(call["actualCallLengthSeconds"])
                            actualCallLengthSeconds.append(call["actualCallLengthSeconds"])
                            #print("")
                            actID.append(actNum)
                        #print("Total in last 10 days:")
                        #print(h["totalRecords"])
                        #print("")
                        #redirect(url_for('callhistory'))
    #print(origNumber,termNumber,startTime,actualCallLengthSeconds,totalRecords,accountName,actID,len(accountName),len(origNumber))
    return render_template('callhistory.html',origNumber=origNumber,termNumber=termNumber,startTime=startTime,actualCallLengthSeconds=actualCallLengthSeconds,totalRecords=totalRecords,totAct = len(accountName),len = len(origNumber),actID=actID,accountName=accountName)





@app.route("/registrationstatus", methods=['GET','POST'])
def registered():
    countA = 1
    headers= apiInfo.headers
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
    #print(q)
    if q!= None:
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

                #q = input("What Account are you looking for\n")

                search = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/search?q=" + q,
                                      headers=headers)
                #print(search)
                actInfo = json.loads(search.text)
                logging.debug("Registered Account Search:" + str(actInfo))
                if search.status_code == 401:
                    if actInfo["message"] == 'Unauthorized' or actInfo["messages"] == 'ExpiredAuthToken':
                        return redirect(url_for('logout'))
                #print(actInfo)

                for x in actInfo:
                    #print(x["id"])
                    Accountid.append(x["id"])
                    #print(x['accountNumber'])
                    #print(x['accountName'])
                    #print('')
                # print(Accountid)
                if len(Accountid) == 0:
                    accountName.append("Not Found")
                    Accountid.append("Not Found")

        for prt in Partitionid:
            partition = requests.get("https://api.alianza.com/v2/partition/" + prt, headers=headers)
            p = json.loads(partition.text)
            logging.debug("Registered Partition Name:" + str(p))
            if partition.status_code == 401:
                if p["message"] == 'Unauthorized' or p["messages"] == 'ExpiredAuthToken':
                    return redirect(url_for('logout'))
            partitionName.append(p["name"])
            for act in Accountid:
                account = requests.get("https://api.alianza.com/v2/partition/" + prt + "/account/" + act, headers=headers)
                a = json.loads(account.text)
                logging.debug("Registered Account Name:" + str(a))
                if account.status_code == 401:
                    if a["message"] == 'Unauthorized' or a["messages"] == 'ExpiredAuthToken':
                        return redirect(url_for('logout'))
                #print(a)
                if account.status_code == 404:
                    pass
                else:
                    accountName.append(a["accountName"])
                    BusinessLines = requests.get(
                        "https://api.alianza.com/v2/partition/"+prt+"/account/"+act+"/deviceline",
                        headers=headers)
                    y = json.loads(BusinessLines.text)
                    logging.debug("Device Lines:" + str(y))
                    if BusinessLines.status_code == 401:
                        if y["message"] == 'Unauthorized' or y["messages"] == 'ExpiredAuthToken':
                            return redirect(url_for('logout'))
                    actNum = actNum + 1
                    for line in y:
                        #print(line)
                        lineName.append(line["deviceName"])  # Line name
                        Phonenumber.append(line["sipUsername"])  # Phonenumber
                        ids = line["id"]
                        registered = requests.get(
                            "https://api.alianza.com/v2/partition/" + prt + "/account/" + act + "/deviceline/" + ids + "/registrationstatus",
                            headers=headers)
                        z = json.loads(registered.text)
                        logging.debug("Line is Registered:" + str(z))
                        if registered.status_code == 401:
                            if z["message"] == 'Unauthorized' or z["messages"] == 'ExpiredAuthToken':
                                return redirect(url_for('logout'))
                        # True/False if line is registered
                        if z["registered"] == True:
                            regStatus.append("Registered")
                        else:
                            regStatus.append("Not Registered")
                        # address = requests.get()
                        actID.append(actNum)
                        redirect(url_for('registered'))
    #print(accountName)
    #print([partitionName,accountName,len(lineName),lineName,Phonenumber, regStatus, actID])
    return render_template('registered.html',partitionName=partitionName,accountName=accountName,len = len(lineName),totAct = len(accountName), lineName=lineName, Phonenumber=Phonenumber,regStatus=regStatus,actID=actID)


@app.route('/logs', methods=['GET', 'POST'])
def logs():
    logging.debug("Download Log")
    return send_file(r'Logs\ProcessLog', as_attachment=True)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logging.debug("Logout:" + apiInfo.headers['X-AUTH-TOKEN'])
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
        logging.debug("Login:"+str(x))
        if response.status_code==201:
            apiInfo.headers['X-AUTH-TOKEN'] = x["authToken"]
            return redirect(url_for('registered'))
        else:
            error = 'Invalid Credentials. Please try again.'
    return render_template('login.html', error=error)




@app.route("/<name>")
def hello(name):
    return f"{escape(name)}, Incorrect URL"


if __name__ == "__main__":
    #app.debug = True
    app.run(host="0.0.0.0",port=80)