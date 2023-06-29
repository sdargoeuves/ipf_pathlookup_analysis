

def display_severity(value: int):
    """
    Display the icon depending on the value
    """
    if value == 0:
        return "✅"  # Green tick
    elif value == 10:
        return "🔵"  # Blue ball
    elif value == 20:
        return "🟠"  # Amber ball or warning
    elif value == 30:
        return "❌"  # Red cross
    else:
        return "❓"  # Question mark or other symbol


def remove_vdevice_id(vdevice_id_name: str):
    """
    Function to remove the vDevice ID and only keep the name of the device
    """
    return (
        vdevice_id_name.split("!")[1]
        if len(vdevice_id_name.split("!")) > 1
        else vdevice_id_name
    )


def replace_vdevice_id(prev_next_edge_dict: dict):
    """
    We check the nextEdgeId and if it contains no hostname (!) we look for it

    pathlookup_edges[prev_next_edge_id]["nextEdgeIds"][0]
    """
    next_edge_id = prev_next_edge_dict["nextEdgeIds"][0]
    if len(next_edge_id.split("!")) != 1:
        return next_edge_id
    device_id = next_edge_id.split("@")[0] if len(next_edge_id.split("@")) > 0 else None
    if device_id:
        hostname = prev_next_edge_dict["id"].split(f"{device_id}!")[1].split("@")[0]
        return next_edge_id.replace(device_id, "!".join([device_id, hostname]))
