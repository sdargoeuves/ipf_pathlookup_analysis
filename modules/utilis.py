"""
Collection of utility functions for various purposes.

This module contains functions that offer convenient utility operations.
Each function serves a specific purpose and is documented individually.

Functions:
-  display_severity(): Display an icon based on the severity value.
-  remove_vdevice_id(): Remove the vDevice ID and return the device name.
-  replace_vdevice_id(): Replace the nextEdgeId with the hostname if missing.

"""
def display_severity(value: int):
    """
    Display the corresponding icon based on the severity value.

    Parameters:
    - value (int): The severity value.

    Returns:
    - str: The icon representing the severity:
        - "✅" for value 0 (Green tick)
        - "🔵" for value 10 (Blue ball)
        - "🟠" for value 20 (Amber ball or warning)
        - "❌" for value 30 (Red cross)
        - "❓" for any other value (Question mark or other symbol)
    """
    if value == 0:
        return "✅"  # Green tick
    elif value == 10:
        return "🔵"  # Blue ball
    elif value == 20:
        return "🟠"  # Amber ball or warning
    elif value == 30:
        return "❌"  # Red cross
    return "❓"  # Question mark or other symbol


def remove_vdevice_id(vdevice_id_name: str, return_device_id: bool = False):
    """
    Removes the vDevice ID from the vdevice_id_name and returns only the device name.

    Parameters:
    - vdevice_id_name (str): The vDevice ID and name string.
    - return_device_id (bool): Flag indicating whether to return the device ID,
    along with the name. Default is False.

    Returns:
    - str or tuple: The device name if return_device_id is False.
                    The device ID and name tuple if return_device_id is True.
                    If vdevice_id_name is empty or doesn't contain a device ID,
                    it returns the input string.
    """
    vdevice_id_name_split = vdevice_id_name.split("!")
    if not return_device_id:
        return (
            vdevice_id_name_split[1]
            if len(vdevice_id_name_split) > 1
            else vdevice_id_name
        )
    if len(vdevice_id_name_split) > 1:
        return (vdevice_id_name_split[1], vdevice_id_name_split[0])
    return (vdevice_id_name, None)


def replace_vdevice_id(prev_next_edge_dict: dict):
    """
    Replaces the nextEdgeId in the prev_next_edge_dict with the hostname if it's missing.

    Parameters:
    - prev_next_edge_dict (dict): Dict representing the previous and next edge information.

    Returns:
    - str or None: The updated nextEdgeId string if a replacement is made.
                  None if the nextEdgeId is already complete or missing device ID.
    """
    next_edge_id = prev_next_edge_dict["nextEdgeIds"][0]
    if len(next_edge_id.split("!")) != 1:
        return next_edge_id
    device_id = next_edge_id.split("@")[0] if len(next_edge_id.split("@")) > 0 else None
    if device_id:
        hostname = prev_next_edge_dict["id"].split(f"{device_id}!")[1].split("@")[0]
        return next_edge_id.replace(device_id, "!".join([device_id, hostname]))
    return None
