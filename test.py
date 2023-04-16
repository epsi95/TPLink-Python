from tplink_python import TPLinkClient
import random


def test():
    """
    Tests and examples
    :return:
    """
    # to get router details
    print("<----------to get router details---------->")
    tp_client = TPLinkClient()
    router_details = tp_client.get_router_details()

    print(router_details)

    # get wan connection status
    print("<----------get wan connection status---------->")
    wan_status = tp_client.get_wan_connection_status()
    print(wan_status)

    # get router total uptime
    print("<----------get router total uptime---------->")
    total_up_time_in_seconds = tp_client.get_router_up_time_in_seconds()
    print('router is up for: ' + str(total_up_time_in_seconds) + ' seconds')

    # check internet link
    print("<----------check internet link---------->")
    internet_link_status = tp_client.check_internet_link_status()
    print('router can connect to IPS: ' + str(internet_link_status.upper() == 'UP'))

    # get all the devices details connected to router
    print("<----------get all the devices details connected to router---------->")
    all_connected_devices = tp_client.get_wireless_connected_devices()
    print(all_connected_devices)

    # get all the whitelisted MAC addresses
    print("<----------get all the whitelisted MAC addresses---------->")
    all_whitelisted_mac_address = tp_client.get_whitelisted_mac_addresses()
    print(all_whitelisted_mac_address)

    # white list a mac
    print("<----------white list a mac---------->")
    random_mac = "02:00:00:%02x:%02x:%02x" % (random.randint(0, 255),
                                              random.randint(0, 255),
                                              random.randint(0, 255))
    mac_whitelist_result = tp_client.whitelist_mac(random_mac, "temporary")
    if "[error]0" not in mac_whitelist_result:
        print("whitelisting not successful", mac_whitelist_result)
    else:
        print("whitelisting successful")

    # remove a mac from whitelist
    print("<----------remove a mac from whitelist---------->")
    remove_result = tp_client.remove_mac_from_whitelist(random_mac)
    if "[error]0" in remove_result:
        print("MAC removal is successful")
    else:
        print("unable to remove MAC", remove_result, random_mac)

    # get wifi connection details
    print("<----------get wifi connection details---------->")
    print(tp_client.get_wifi_connection_details())

    # router reboot
    print("<----------router reboot---------->")
    reboot = tp_client.reboot()
    if reboot == "[error]0":
        print("reboot successful")
    else:
        print("reboot not successful")


test()
