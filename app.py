import params as my
import requests
import json
import time
from datetime import datetime


def getTimeStempStr():
    return "[" + datetime.now().strftime("%B %d, %Y %H:%M:%S") + "]"


class MyReq:
    url = ""
    headers = {}
    data = {}
    def Execute(self):
        response = requests.request("GET", self.url, headers=self.headers, data=self.data)
        return response

class KismetClient:
    def __init__(self, server_, port_, login_, pass_):
        self.__server = server_
        self.__port = port_
        self.__login = login_
        self.__password = pass_
        self.__cookie = self.__GetAuthCookie()

    __cookie = ""
    __login = ""
    __password = ""
    __server = ""
    __port = ""

    def __GetAuthCookie(self):
        authReq = MyReq()
        authReq.url = "http://"+self.__login+":"+self.__password+"@"+self.__server+":"+self.__port+"/session/check_session"

        authResponse = authReq.Execute()

        cookieTemp = authResponse.headers["Set-Cookie"]
        cookieEnd = cookieTemp.find(";")
        return cookieTemp[0:cookieEnd]

    
    def GetDevicesData(self, minutes):
        deviceReq = MyReq()
        timeStamp = str(int(time.time()) - minutes*60)
        deviceReq.url = "http://"+self.__server+":"+self.__port+"/devices/last-time/"+timeStamp+"/devices.json"
        deviceReq.headers = {
            "Cookie": self.__cookie,
            "charset": "utf-8"
        }
        deviceResponse = deviceReq.Execute()
        return json.loads(deviceResponse.text)

    def GetAertData(self, minutes):
        alerReq = MyReq()
        timeStamp = str(int(time.time()) - minutes*60)
        alerReq.url = "http://"+self.__server+":"+self.__port+"/alerts/last-time/"+timeStamp+"/alerts.json"
        alerReq.headers = {
            "Cookie": self.__cookie,
            "charset": "utf-8"
        }
        alertResponse = alerReq.Execute()
        return json.loads(alertResponse.text)

    def GetAllAlertsData(self):
        alerReq = MyReq()
        alerReq.url = "http://"+self.__server+":"+self.__port+"/alerts/all_alerts.json"
        alerReq.headers = {
            "Cookie": self.__cookie,
            "charset": "utf-8"
        }
        alertResponse = alerReq.Execute()
        return json.loads(alertResponse.text)

class KismetMonitor(KismetClient):
    
    def __init__(self, server_, port_, login_, pass_, monitoredSSIDs__):
        super().__init__(server_, port_, login_, pass_)
        self.__mointoredSSIDs = monitoredSSIDs__

    def __del__(self):
        if self.__logFile:
            self.__logFile.close()
            print("Closing the log file " + self.__logFileName)

    __mointoredSSIDs = []
    __refreshRateMin = 60
    __lastScanDeviceData = {}
    __clientMapFileName = ""
    __clientMap = {}
    __logFileName = ""
    __logFile = None
    __receivedAlerts = []
    __hadFirstScan = False


    def __ScanDeviceData(self):
        self.__lastScanDeviceData = super().GetDevicesData(self.__refreshRateMin)
        return self.__lastScanDeviceData

    def __ScanAertData(self):
        if not self.__hadFirstScan:
            alertData = super().GetAllAlertsData()
            self.__hadFirstScan = True
        else:
            alertData = super().GetAertData(self.__refreshRateMin)
        
        for i, alert in enumerate(alertData):
            if alert["kismet.alert.hash"] not in self.__receivedAlerts:
                self.__receivedAlerts.append(alert["kismet.alert.hash"])
                print(" !!! New Alert: " + "[PRIORITY="+str(alert["kismet.alert.severity"])+"] "+"[CLASS="+alert["kismet.alert.class"]+"] "+alert["kismet.alert.text"])
                self.__LogNewAlert(alert)
    
    def __LogNewAlert(self, alert):
        AlertMessage = getTimeStempStr() + "[Kismet Alert][PRIORITY="+str(alert["kismet.alert.severity"])+"] "+"[CLASS="+alert["kismet.alert.class"]+"] "+alert["kismet.alert.text"]
        self.__logFile.write(AlertMessage)

    def __ScanDevicesInMonitoredSSIDs(self):
        isClientMapChanged = False
        for i, device in enumerate(self.__lastScanDeviceData):
            if self.__IsDeviceAccessPoint(device) and self.__IsDeviceMonitoredAccessPoint(device) and self.__DoesAccessPointHasClientDevices(device):
                
                print(getTimeStempStr() +"Connected devices in last " + str(self.__refreshRateMin) + " minutes to Network \"" + device["kismet.device.base.commonname"] + "\" with MAC: " + device["kismet.device.base.macaddr"] + " -- manufacture: "+device["kismet.device.base.manuf"]+ ":")
                
                for client in self.__GetAccessPointClientDevices(device):
                    manufacture = str(self.__FindClientDataManufacture(client))
                    if client not in self.__clientMap["knownClients"]:
                        print("  " + client + " -- manufacture: " + manufacture + " [New Clinet]")
                        self.__clientMap["knownClients"].append(str(client))
                        isClientMapChanged = True
                        self.__LogNewClient(client)
                    else:
                        print("  " + client + " -- manufacture: " + manufacture )
                    

                print("")
        if isClientMapChanged == True:
            self.__OverrideClientMapFile()

    def __LogNewClient(self, clientMac):
        AlertMessage = getTimeStempStr() + "[Allert] New Client connected to monitored Access Point: [" + clientMac + "] manufactured by: "+str(self.__FindClientDataManufacture(clientMac)) + "\n"
        self.__logFile.write(AlertMessage)

    def __OverrideClientMapFile(self):
        file = open(self.__clientMapFileName, "w")
        file.write(json.dumps(self.__clientMap))
        file.close()

    def __FindClientDataManufacture(self, clientMac):
        for i, device in enumerate(self.__lastScanDeviceData):
            if device["kismet.device.base.macaddr"] == clientMac:
                return device["kismet.device.base.manuf"]


    def __IsDeviceAccessPoint(self, deviceJson):
        return deviceJson["kismet.device.base.type"] == "Wi-Fi AP"
    
    def __IsDeviceMonitoredAccessPoint(self, deviceJson):
        return deviceJson["kismet.device.base.commonname"] in self.mointoredSSIDs

    def __DoesAccessPointHasClientDevices(self, accessPointJson):
        return bool("dot11.device.associated_client_map" in list(accessPointJson["dot11.device"]))

    def __GetAccessPointClientDevices(self, accessPointJson):
        return accessPointJson["dot11.device"]["dot11.device.associated_client_map"]

    def Scan(self, refreshRate):
        self.__logFileName = "Log/KismetMonitorLogFile" + getTimeStempStr() +".log"
        self.__logFile = open(self.__logFileName, "w")
        print("Created a log file: "+self.__logFileName+". Any alerts will be saved to that file.")
        self.__InitClientMap()
        self.__refreshRateMin = refreshRate
        while(True):
            print("--------------------------------------------------------------------------------------")
            self.__ScanDeviceData()
            self.__ScanDevicesInMonitoredSSIDs()
            self.__ScanAertData()
            time.sleep(self.__refreshRateMin * 60)

    def SetDataFile(self, fileName):
        self.__clientMapFileName = fileName

    def __InitClientMap(self):
        if self.__clientMapFileName == "":
            return
        try:
            clientMapFile = open(self.__clientMapFileName, "r")
            self.__clientMap = json.load(clientMapFile)
            clientMapFile.close()
            print("Clients map file " + self.__clientMapFileName + " has been loaded.")
        except:
            print("Failed to load file " + self.__clientMapFileName + ". File will be created automatically.")
            self.__clientMap = {"knownClients": []}

def Main():
    customRefreshRateInMin = 0.1
    kisMon = KismetMonitor(my.kismetServer, my.kismetPort, my.kismetLogin, my.kismetPass, my.wifiSSIDs)
    kisMon.SetDataFile("clinetMap.json")
    kisMon.Scan(customRefreshRateInMin)


if __name__ == "__main__":
    Main()