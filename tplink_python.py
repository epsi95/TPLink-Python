import requests
import base64
import re
import string


class TPLinkClient(object):
    def __init__(self, username='', password='', router_url="192.168.0.1"):
        self.username = username
        self.password = password
        self.router_url = router_url
        self.connection_string = '{}:{}'.format(self.username, self.password)
        self.auth_token = 'Authorization=Basic {}'.format(
            base64.b64encode(self.connection_string.encode('ascii')).decode('ascii'))
        self.AUTH_HEADER = {
            'host': self.router_url,
            'proxy-connection': 'keep-alive',
            'content-type': 'text/plain',
            'accept': '*/*',
            'origin': 'http://' + self.router_url,
            'referer': 'http://' + self.router_url + '/mainFrame.htm',
            'accept-encoding': 'gzip, deflate',
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            'cookie': self.auth_token,
            'sec-gpc': '1'
        }
        self.NO_AUTH_HEADER = {
            'host': self.router_url,
            'proxy-connection': 'keep-alive',
            'content-type': 'text/plain',
            'accept': '*/*',
            'origin': 'http://' + self.router_url,
            'referer': 'http://' + self.router_url + '/qr.htm',
            'accept-encoding': 'gzip, deflate',
            'accept-language': 'en-GB,en-US;q=0.9,en;q=0.8',
            'sec-gpc': '1'
        }

    def get_router_details(self):
        """
        Returns generic Router details.
        User Authentication not required, only router_url should be accessible.

        >>> tp_client = TPLinkClient()
        >>> tp_client.get_router_details()
        Output
        -------
        {
            'modelName': 'TL-XXXXXX',
            'description': 'TP-Link Wireless N Router XXXXXX',
            'mode': 'Router',
            'clientIp': '192.168.0.100',
            'clientMac': 'a7:ea:b4:c0:1b:e8',
            'userType': 'User'
        }

        :return: Python dict object containing router details
        """
        url = "http://" + self.router_url + "/cgi?1&1&1&8"
        payload = "[IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]0," \
                  "4\r\nmodelName\r\ndescription\r\nX_TP_isFD\r\nX_TP_ProductVersion\r\n[ETH_SWITCH#0,0,0,0,0,0#0,0," \
                  "0,0,0,0]1,1\r\nnumberOfVirtualPorts\r\n[MULTIMODE#0,0,0,0,0,0#0,0,0,0,0,0]2,1\r\nmode\r\n[" \
                  "/cgi/info#0,0,0,0,0,0#0,0,0,0,0,0]3,0\r\n "
        headers = self.NO_AUTH_HEADER
        response = requests.post(url, headers=headers, data=payload).text
        model_name = re.findall(r"(?i)modelName=(?P<modelName>.+)", response)[0].strip()
        description = re.findall(r"(?i)description=(?P<description>.+)", response)[0].strip()
        mode = re.findall(r"(?i)mode=(?P<mode>.+)", response)[0].strip()
        client_ip = re.findall(r"(?i)clientIp=\"(?P<clientIp>.+)\"", response)[0].strip()
        client_mac = re.findall(r"(?i)clientMac=\"(?P<clientMac>.+)\"", response)[0].strip()
        user_type = re.findall(r"(?i)userType=\"(?P<userType>.+)\"", response)[0].strip()
        return ({"modelName": model_name,
                 "description": description,
                 "mode": mode,
                 "clientIp": client_ip,
                 "clientMac": client_mac,
                 "userType": user_type
                 })

    def get_wan_connection_status(self):
        """
        Returns router WAN connection details.
        User Authentication is required.

        >>> tp_client = TPLinkClient()
        >>> wan_status = tp_client.get_wan_connection_status()
        >>> print(wan_status)
        Output
        -------
        {
            'enable': '0',
            'connectionStatus': 'Unconfigured',
            'connectionType': 'IP_Routed',
            'PPPoESessionID': '0',
            'defaultGateway': '0.0.0.0',
         }

        :return: Python dict object containing WAN connection details
        """
        url = "http://" + self.router_url + "/cgi?1&1"
        payload = "[WAN_PPP_CONN#1,1,1,0,0,0#0,0,0,0,0,0]0,0\r\n[WAN_IP_CONN#1,1,2,0,0,0#0,0,0,0,0,0]1,0\r\n"
        headers = self.AUTH_HEADER
        response = requests.request("POST", url, headers=headers, data=payload).text
        return dict(re.findall(r"(?:(?P<key>.+)=(?P<val>.+))", response, re.MULTILINE))

    def get_router_up_time_in_seconds(self):
        """
        Returns router's up time in seconds.
        User Authentication is required.

        >>> tp_client = TPLinkClient()
        >>> total_up_time_in_seconds = tp_client.get_router_up_time_in_seconds()
        >>> print('router is up for: ' + str(total_up_time_in_seconds) + ' seconds')
        Output
        -------
        router is up for: 12455 seconds

        :return: python int for number of seconds
        """
        url = "http://" + self.router_url + "/cgi?1&1&1"
        payload = "[AUTO_REBOOT_CFG#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n[HOUR#0,0,0,0,0,0#0,0,0,0,0,0]1,1\r\nyear\r\n[" \
                  "IGD_DEV_INFO#0,0,0,0,0,0#0,0,0,0,0,0]2,1\r\nupTime\r\n "
        headers = self.AUTH_HEADER
        response = requests.post(url, headers=headers, data=payload).text
        return int(re.findall(r"(?i)(?:upTime=(\d+))", response)[0])

    def check_internet_link_status(self):
        """
        Returns the status of the connection between your router and the modem


        >>> tp_client = TPLinkClient()
        >>> internet_link_status = tp_client.check_internet_link_status()
        >>> print('router can connect to IPS: ' + str(internet_link_status.upper() == 'UP'))
        Output
        -------
        router can connect to IPS: True

        :return: Python str giving the status
        """
        url = "http://" + self.router_url + "/cgi?1"
        payload = "[WAN_ETH_INTF#1,0,0,0,0,0#0,0,0,0,0,0]0,1\r\nstatus\r\n"
        headers = self.AUTH_HEADER
        response = requests.post(url, headers=headers, data=payload).text
        return re.findall(r"(?i)(?:status=(\S+))", response)[0]

    def get_wireless_connected_devices(self):
        """
        Returns the details of devices connected wireless

        >>> all_connected_devices = tp_client.get_wireless_connected_devices()
        >>> print(all_connected_devices)
        Output
        -------
        [
            {
                'associatedDeviceMACAddress': 'a7:ea:b4:c0:1b:e8',
                'X_TP_TotalPacketsSent': '328263',
                'X_TP_TotalPacketsReceived': '52826',
                'X_TP_HostName': 'wlan0'
            }
        ]

        :return: Python list with dict each representing individual user
        """
        url = "http://" + self.router_url + "/cgi?6"
        payload = "[LAN_WLAN_ASSOC_DEV#0,0,0,0,0,0#1,1,0,0,0,0]0," \
                  "4\r\nAssociatedDeviceMACAddress\r\nX_TP_TotalPacketsSent\r\nX_TP_TotalPacketsReceived\r" \
                  "\nX_TP_HostName\r\n "
        headers = self.AUTH_HEADER
        response = requests.post(url, headers=headers, data=payload).text
        regex = (r"(?i)(?:associatedDeviceMACAddress=(?P<associatedDeviceMACAddress>\S+)\n"
                 r"X_TP_TotalPacketsSent=(?P<X_TP_TotalPacketsSent>\S+)\n"
                 r"X_TP_TotalPacketsReceived=(?P<X_TP_TotalPacketsReceived>\S+)\n"
                 r"X_TP_HostName=(?P<X_TP_HostName>\S+)\n"
                 r")")
        connected_devices = []
        for each_device_data in re.findall(regex, response, re.MULTILINE):
            connected_devices.append(dict(zip(['associatedDeviceMACAddress',
                                               'X_TP_TotalPacketsSent',
                                               'X_TP_TotalPacketsReceived',
                                               'X_TP_HostName'], each_device_data)))
        return connected_devices

    def get_whitelisted_mac_addresses(self):
        """
        Returns the list of whitelisted MACs in MAC filtering section

        >>> all_whitelisted_mac_address = tp_client.get_whitelisted_mac_addresses()
        >>> print(all_whitelisted_mac_address)
        Output
        -------
        [
            {
                'id': '[1,1,1,0,0,0]',
                'enabled': '1',
                'MACAddress': 'a7:ea:b4:c0:1b:e8',
                'description': 'James's Mac',
                'hostName': 'wlan0'
            }
        ]

        :return: Python list with dict each representing individual whitelisted MAC details
        """
        url = "http://" + self.router_url + "/cgi?6"
        payload = "[LAN_WLAN_MACTABLEENTRY#0,0,0,0,0,0#1,1,0,0,0,0]0," \
                  "4\r\nEnabled\r\nMACAddress\r\nDescription\r\nHostName\r\n "
        headers = self.AUTH_HEADER
        response = requests.request("POST", url, headers=headers, data=payload).text
        regex = (r"(?i)(?:(?P<id>\[[\d,]+]).*\n"
                 r"enabled=(?P<enabled>\d+).*\n"
                 r"MACAddress=(?P<MACAddress>.*)\n"
                 r"description=(?P<description>.*)\n"
                 r"hostName=(?P<hostName>.*)\n"
                 r")")
        white_listed_macs = []
        for each_white_listed_mac in re.findall(regex, response, re.MULTILINE):
            white_listed_macs.append(dict(zip(["id",
                                               "enabled",
                                               "MACAddress",
                                               "description",
                                               "hostName"], each_white_listed_mac)))
        return white_listed_macs

    def whitelist_mac(self, mac_address, description):
        """
        Returns status of whitelisting

        >>> mac_whitelist_result = tp_client.whitelist_mac("02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                                                                    random.randint(0, 255),
                                                                                    random.randint(0, 255)), "temporary")
        >>> if "[error]0" not in mac_whitelist_result:
                print("whitelisting not successful", mac_whitelist_result)
            else:
                print("whitelisting successful")
        Output
        -------
        whitelisting successful

        :param mac_address: MAC address to be whitelisted
        :param description: user-friendly name of the MAC address
        :return: Python str "[error]0" means success
        """
        if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac_address.lower()):
            if len(set(string.punctuation).intersection(description)) > 0:
                raise Exception("special characters not allowed in description")
            # source https://stackoverflow.com/questions/7629643/how-do-i-validate-the-format-of-a-mac-address
            url = "http://" + self.router_url + "/cgi?3"
            payload = "[LAN_WLAN_MACTABLEENTRY#0,0,0,0,0,0#1,1,0,0,0,0]0," \
                      "4\r\nEnabled=1\r\nDescription=" + description + "\r\nMACAddress="+ mac_address + "\r\nHostName=wlan0\r\n "
            headers = self.AUTH_HEADER
            response = requests.request("POST", url, headers=headers, data=payload).text
            return response
        else:
            raise Exception("Please provide a valid MAC address")

    def remove_mac_from_whitelist(self, mac_address):
        """
        Returns status of removal of MAC address from whitelisted

        >>> random_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                          random.randint(0, 255),
                                          random.randint(0, 255))

        >>> if "[error]0" in tp_client.whitelist_mac(random_mac, "temporary"):
                remove_result = tp_client.remove_mac_from_whitelist(random_mac)
                if "[error]0" in remove_result:
                    print("MAC removal is successful")
        Output
        -------
        MAC removal is successful

        :param mac_address: valid MAC address to be removed
        :return: Python str "[error]0" means success
        """
        url = "http://" + self.router_url + "/cgi?4"
        listed_mac_addresses = self.get_whitelisted_mac_addresses()
        id_of_the_mac = None
        for each_mac_address in listed_mac_addresses:
            if each_mac_address["MACAddress"].lower() == mac_address.lower():
                id_of_the_mac = each_mac_address["id"][1:-1]
        if id_of_the_mac:
            payload = "[LAN_WLAN_MACTABLEENTRY#" + id_of_the_mac + "#0,0,0,0,0,0]0,0\r\n"
            headers = self.AUTH_HEADER
            response = requests.request("POST", url, headers=headers, data=payload).text
            return response
        else:
            return "MAC address is not present in white list"

    def get_wifi_connection_details(self):
        """
        Returns SSID and password of wifi connection

        >>> print(tp_client.get_wifi_connection_details())
        Output
        -------
        {'SSID': 'TP-Link_XXXXE', 'X_TP_PreSharedKey': '1234'}

        :return: Python dict
        """
        url = "http://" + self.router_url + "/cgi?5"
        payload = "[LAN_WLAN#0,0,0,0,0,0#0,0,0,0,0,0]0," \
                  "16\r\nname\r\nSSID\r\nEnable\r\nX_TP_Configuration_Modified\r\nbeaconType\r\nStandard\r" \
                  "\nWEPEncryptionLevel\r\nWEPKeyIndex\r\nBasicEncryptionModes\r\nBasicAuthenticationMode\r" \
                  "\nWPAEncryptionModes\r\nWPAAuthenticationMode\r\nIEEE11iEncryptionModes\r" \
                  "\nIEEE11iAuthenticationMode\r\nX_TP_PreSharedKey\r\nX_TP_GroupKeyUpdateInterval\r\n "
        headers = self.AUTH_HEADER
        response = requests.request("POST", url, headers=headers, data=payload).text
        ssid = re.findall(r"(?i)SSID=(\S+)", response)[0]
        x_tp_pre_shared_key = re.findall(r"(?i)X_TP_PreSharedKey=(\S+)", response)[0]
        return {"SSID": ssid, "X_TP_PreSharedKey": x_tp_pre_shared_key}



