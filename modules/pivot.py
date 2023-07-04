"""
Utility functions for IPFabric analysis.

This module provides utility functions for various IPFabric analysis tasks. It includes
functions for finding device serial numbers, retrieving entry point information from
pathlookup graph data, and other related operations.

Functions:
-  find_device_sn(device_id, pathlookup_nodes): Find and return the serial number of a
  device based on its device ID.
-  return_entry_point_pivot(pathlookup_json): Retrieve the device serial number, interface
  name, and hostname for the entry point device.

Constants:
-  GREEN: The value representing a "Green" status.
-  BLUE: The value representing a "Blue" status.
-  AMBER: The value representing an "Amber" status.
-  RED: The value representing a "Red" status.
-  COLOUR_DICT: A dictionary mapping color names to color values.
-  STOP_TRACE: A list of trace statuses to denote stopping points.
-  EVENT_HEADER_TYPE: A tuple of header types for events.
-  L2_EXCLUSION_PROTOCOL: A tuple of L2 exclusion protocols.
-  CHAIN_SWITCHING: The value representing chain switching.
"""
from utilis import remove_vdevice_id


def find_device_sn(device_id: str, pathlookup_nodes: dict) -> str:
    """
    Find and return the serial number of a device based on its device ID.

    Parameters:
    - device_id (str): The device ID to search for.
    - pathlookup_nodes (dict): The dictionary containing the pathlookup nodes.

    Returns:
    - str: The serial number of the device, or an empty string if the device ID is not found.
    """
    # for node, node_data in pathlookup_nodes.items():
    #     if node == device_id:
    #         return node_data["sn"]
    # return ""
    return next(
        (
            node_data["sn"]
            for node, node_data in pathlookup_nodes.items()
            if node == device_id
        ),
        "",
    )


def return_entry_point_pivot(pathlookup_json: dict) -> dict:
    """
    Retrieve the device serial number, interface name, and hostname for the entry point device
    based on the pathlookup graph data.

    Parameters:
    - pathlookup_json (dict): The pathlookup graph data in JSON format.

    Returns:
    - dict or None: A dictionary containing the device serial number, interface name, and hostname
                    of the entry point device. Returns None if the entry point device is not found.
    """
    pathlookup_edges = pathlookup_json["graphResult"]["graphData"]["edges"]
    pathlookup_nodes = pathlookup_json["graphResult"]["graphData"]["nodes"]
    for edge, edge_data in pathlookup_edges.items():
        if "--transit" in edge:
            interface_name = edge_data["sourceIfaceName"]
            device_id = edge_data["source"]
            device_name = remove_vdevice_id(str(edge).split('@', maxsplit=1)[0])
            device_sn = find_device_sn(device_id, pathlookup_nodes)
            return {"sn": device_sn, "iface": interface_name, "hostname": device_name}
    return None
