<!-- tplink-python documentation master file, created by
sphinx-quickstart on Thu Apr 22 23:47:39 2021.
You can adapt this file completely to your liking, but it should at least
contain the root `toctree` directive. -->
# Welcome to tplink-python’s documentation!

# Contents:


* test module


* tplink_python module


# Indices and tables


* Index


* Module Index


* Search Page
# test module


### test.test()
Tests and examples
:return:
# tplink_python module


### class tplink_python.TPLinkClient(username='', password='', router_url='192.168.0.1')
Bases: `object`


#### \__init__(username='', password='', router_url='192.168.0.1')
Initialize self.  See help(type(self)) for accurate signature.


#### check_internet_link_status()
Returns the status of the connection between your router and the modem

```python
>>> tp_client = TPLinkClient()
>>> internet_link_status = tp_client.check_internet_link_status()
>>> print('router can connect to IPS: ' + str(internet_link_status.upper() == 'UP'))
Output
-------
router can connect to IPS: True
```


* **Returns**

    Python str giving the status



#### get_router_details()
Returns generic Router details.
User Authentication not required, only router_url should be accessible.

```python
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
```


* **Returns**

    Python dict object containing router details



#### get_router_up_time_in_seconds()
Returns router’s up time in seconds.
User Authentication is required.

```python
>>> tp_client = TPLinkClient()
>>> total_up_time_in_seconds = tp_client.get_router_up_time_in_seconds()
>>> print('router is up for: ' + str(total_up_time_in_seconds) + ' seconds')
Output
-------
router is up for: 12455 seconds
```


* **Returns**

    python int for number of seconds



#### get_wan_connection_status()
Returns router WAN connection details.
User Authentication is required.

```python
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
```


* **Returns**

    Python dict object containing WAN connection details



#### get_whitelisted_mac_addresses()
Returns the list of whitelisted MACs in MAC filtering section

```python
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
```


* **Returns**

    Python list with dict each representing individual whitelisted MAC details



#### get_wifi_connection_details()
Returns SSID and password of wifi connection

```python
>>> print(tp_client.get_wifi_connection_details())
Output
-------
{'SSID': 'TP-Link_XXXXE', 'X_TP_PreSharedKey': '1234'}
```


* **Returns**

    Python dict



#### get_wireless_connected_devices()
Returns the details of devices connected wireless

```python
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
```


* **Returns**

    Python list with dict each representing individual user



#### remove_mac_from_whitelist(mac_address)
Returns status of removal of MAC address from whitelisted

```python
>>> random_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                  random.randint(0, 255),
                                  random.randint(0, 255))
```

```python
>>> if "[error]0" in tp_client.whitelist_mac(random_mac, "temporary"):
        remove_result = tp_client.remove_mac_from_whitelist(random_mac)
        if "[error]0" in remove_result:
            print("MAC removal is successful")
Output
-------
MAC removal is successful
```


* **Parameters**

    **mac_address** – valid MAC address to be removed



* **Returns**

    Python str “[error]0” means success



#### whitelist_mac(mac_address, description)
Returns status of whitelisting

```python
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
```


* **Parameters**

    
    * **mac_address** – MAC address to be whitelisted


    * **description** – user-friendly name of the MAC address



* **Returns**

    Python str “[error]0” means success



#### reboot()
Returns status of reboot

```python
>>> reboot = tp_client.reboot()
>>> if reboot == ""[error]0"":
        print("reboot successful")
    else:
        print("reboot not successful")
Output
-------
reboot successful
```


* **Returns**

    Python str “[error]0” means success
