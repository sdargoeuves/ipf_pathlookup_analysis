from ipfabric.diagrams import Algorithm, EntryPoint, IPFDiagram, OtherOptions, Unicast
from rich import print
from ipdb import set_trace as debug
from .utilis import remove_vdevice_id

GREEN = "0"
BLUE = "10"
AMBER = "20"
RED = "30"
COLOUR_DICT = {"Green": GREEN, "Blue": BLUE, "Amber": AMBER, "Red": RED}
STOP_TRACE = ["dropped", "accepted"]
EVENT_HEADER_TYPE = ("vxlan", "capwap", "gre", "esp", "mpls", "ip", "fp")
L2_EXCLUSION_PROTOCOL = ("l2", "fp")
CHAIN_SWITCHING = "switching-nexthop"


def find_device_sn(device_id, pathlookup_nodes):
    """
    Parameters:
    device_id (str): The device ID to search for.
    pathlookup_nodes (dict): The dictionary containing the pathlookup nodes.

    Returns:
    str: The serial number of the device.
    """
    for node in pathlookup_nodes.keys():
        if node == device_id:
            return pathlookup_nodes[node]["sn"]

def return_entry_point_pivot(pathlookup_json: dict):
    """This function is used to retrieve the device serial number, interface name and hostname
    of the entry point device in a network based on the pathlookup graph data.
    Args:
        pathlookup_json (dict): The pathlookup graph data in json format

    Returns:
        list: A list of dictionaries containing the device serial number, interface name and hostname
    """
    pathlookup_edges = pathlookup_json["graphResult"]["graphData"]["edges"]
    pathlookup_nodes = pathlookup_json["graphResult"]["graphData"]["nodes"]
    for edge in pathlookup_edges.keys():
        if "--transit" in edge:
            interface_name = pathlookup_edges[edge]["sourceIfaceName"]
            device_id = pathlookup_edges[edge]["source"]
            device_name = remove_vdevice_id(str(edge).split("@")[0])
            device_sn = find_device_sn(device_id=device_id, pathlookup_nodes=pathlookup_nodes)
            return [{"sn": device_sn, "iface":interface_name, "hostname":device_name}]
    return []

