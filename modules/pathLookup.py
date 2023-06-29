from ipfabric import IPFClient
from ipfabric.diagrams import Algorithm, EntryPoint, IPFDiagram, OtherOptions, Unicast
from .pivot import return_entry_point_pivot
from .utilis import display_severity, remove_vdevice_id, replace_vdevice_id
from rich import print
from ipdb import set_trace as debug

GREEN = "0"
BLUE = "10"
AMBER = "20"
RED = "30"
COLOUR_DICT = {"Green": GREEN, "Blue": BLUE, "Amber": AMBER, "Red": RED}
STOP_TRACE = ["dropped", "accepted"]
EVENT_HEADER_TYPE = ("vxlan", "capwap", "gre", "esp", "mpls", "ip", "fp")
L2_EXCLUSION_PROTOCOL = ("l2", "fp")
CHAIN_SWITCHING = "switching-nexthop"



def get_zonefw_interfaces(
    base_url: str,
    auth: str,
    snapshot_id: str,
    ipf_verify: bool=False,
    timeout: int=10
):
    """
    Get from IP Fabric the tables containing the ZoneFW per Interfaces
    """
    ipf = IPFClient(
        base_url=base_url,
        auth=auth,
        snapshot_id=snapshot_id,
        verify=ipf_verify,
        timeout=timeout
    )
    return ipf.technology.security.zone_firewall_interfaces.all()


def get_json_pathlookup(
    base_url: str,
    auth: str,
    snapshot_id: str,
    src_ip: str,
    dst_ip: str,
    protocol: str,
    src_port: str,
    dst_port: str,
    ttl: str,
    fragment_offset: str,
    secured_path: bool,
    pivot: str=None,
    ipf_verify: bool=False,
    ipf_timeout: int=10,
    ipf_diagram: IPFDiagram=None,
    ipf_close: bool=True
):
    """
    Call IP Fabric with the given parameters and return the resulting JSON output.

    Parameters:
    src_ip (str): The source IP address.
    dst_ip (str): The destination IP address.
    protocol (str): The IP protocol to use (e.g. "tcp", "udp").
    src_port (str): The source port number.
    dst_port (str): The destination port number.
    ttl (str): The time-to-live (TTL) value.
    fragment_offset (str): The fragment offset value.
    secured_path (bool): Whether to use a secured path or not.

    Returns:
    str: The JSON file returned by IP Fabric.
    """
    # Initialize an IPFDiagram object with the given parameters
    firstHopAlgorithm = {"type": "automatic"}
    if not ipf_diagram:
        ipf_diagram = IPFDiagram(
            base_url=base_url,
            auth=auth,
            snapshot_id=snapshot_id,
            verify=ipf_verify,
            timeout=ipf_timeout
        )
    if pivot:
        pivot_pathlookup_result = get_json_pathlookup(
            base_url=base_url,
            auth=auth,
            snapshot_id=snapshot_id,
            ipf_diagram=ipf_diagram,
            src_ip=pivot,
            dst_ip=src_ip,
            protocol=protocol,
            src_port=src_port,
            dst_port=dst_port,
            ttl=ttl,
            fragment_offset=fragment_offset,
            secured_path=False,
            ipf_close=False
        )
        if entry_point := return_entry_point_pivot(pivot_pathlookup_result):
            pivot_msg = f"[blue][italic][bold]Info: [/bold][/blue][/italic]Entry point for the source `{src_ip} is: `{entry_point['hostname']}@{entry_point['iface']}`"
            firstHopAlgorithm = Algorithm(entryPoints=[entry_point])
        else:
            pivot_msg = f"[yellow][italic][bold]Warning: [/bold][/yellow][/italic]Pivot `{pivot}` will not be used. From the pivot to the source `({src_ip})` there is no transit."
        print(pivot_msg)

    uni = Unicast(
        startingPoint=src_ip,
        destinationPoint=dst_ip,
        protocol=protocol,
        srcPorts=src_port,
        dstPorts=dst_port,
        ttl=ttl,
        fragmentOffset=fragment_offset,
        securedPath=secured_path,
        firstHopAlgorithm=firstHopAlgorithm,
    )

    # Call IP Fabric and retrieve the path lookup JSON file
    pathlookup_json = ipf_diagram.diagram_json(uni)

    # Close the IPFDiagram object
    if ipf_close:
        ipf_diagram.close()

    # Return the JSON file
    return pathlookup_json


def display_summary_topics(pathlookup_result: dict):
    """
    Display summary information, highlighting issues with NAT, ACL, etc.

    Parameters:
    pathlookup_result (dict): A dictionary containing the results of the path lookup operation.

    Returns:
    None
    """
    # Initialize a dictionary to store the summary information for each topic
    topics_results = {}

    # Print the Summary header
    print("[bold]  - Summary[/bold]")

    # Iterate over each topic in the eventsSummary dictionary
    for topic, topic_data in pathlookup_result["eventsSummary"]["topics"].items():
        topics_results[topic] = []

        # Iterate over each color in the COLOUR_DICT dictionary
        for colour in COLOUR_DICT:
            value = topic_data.get(COLOUR_DICT[colour], 0)

            # If the color value is not zero, add it to the list of results for this topic
            if value != 0:
                topics_results[topic].append(f"      - {colour}: {value}")

    # Display the summary information for each topic
    if not any(topics_results.values()):
        print("No summary information for this path")
    else:
        for topic, topic_results in topics_results.items():
            if topic_results:
                print(f"    - {topic}")
                print("\n".join(f"{result}" for result in topic_results))


def display_summary_global(pathlookup_result: dict):
    """
    Display information related to the Global key.

    Parameters:
    pathlookup_result (dict): A dictionary containing the results of the path lookup operation.

    Returns:
    None
    """
    # Check if there is any Global information to display
    if len(pathlookup_result["eventsSummary"]["global"]) > 0:
        global_info = pathlookup_result["eventsSummary"]["global"]

        # Print the Global information header
        print("[bold]  - Global[/bold]")

        # Print each piece of Global information
        for info in global_info:
            message = [info["name"]]
            message.extend(info["details"])
            message.append(str(info["severity"]))
            message = " | ".join(message)
            print(f"{message}")


def display_all_edges(pathlookup_edges: dict):
    """
    Display all edges in the path, highlighting when multiple egress points exist.

    Parameters:
    pathlookup_edges (dict): A dictionary containing information about the edges in the path.

    Returns:
    list: A list of all edges involved in the path.
    """
    # Collect all next edge IDs in a list
    next_edge_ids = [next(iter(pathlookup_edges.values()))["id"]]
    for edge in pathlookup_edges.values():
        if len(edge["nextEdgeIds"]) > 1:
            next_edge_ids.extend(
                f"{path}--multiple-egress" for path in edge["nextEdgeIds"]
            )
        elif len(edge["nextEdgeIds"]) == 1:
            next_edge_ids.append(edge["nextEdgeIds"][0])
        # else:
        #     next_edge_ids.append("no_next_edge")

    # Process each edge ID to extract the relevant information
    processed_edges = []
    for edge in next_edge_ids:
        processed_edge = edge.split("--")
        processed_edge = [
            f"{e.split('!')[1]}"
            if "!" in e
            else f"{e.split('@')[1]}"
            if "@" in e
            else e
            for e in processed_edge
        ]
        processed_edges.append("--".join(processed_edge))

    # Print the list of edges, highlighting multiple egress points
    final_all_edges = []
    prev_device_src = ""
    for edge in processed_edges:
        if edge not in final_all_edges:
            final_all_edges.append(edge)
            device_src = edge.split("@")[0] if edge.split("@") else ""
            if device_src == prev_device_src:
                print("".join([" └ ", edge])) if "multiple-egress" in edge else print(
                    edge
                )
            else:
                print(edge)
            prev_device_src = device_src

    return final_all_edges


def follow_path_first_option(pathlookup_edges: dict):
    """
    Follow a path starting from the beginning and always take the first option when there are multiple choices for the egress interface.

    Parameters:
    pathlookup_edges (dict): A dictionary containing information about the edges in the path.

    Returns:
    List of edges involved in the Path (always selecting the first option if multiple choices)
    """

    # Start from the first entry in the pathlookup_edges dictionary
    first_edge = next(iter(pathlookup_edges.values()))

    # Initialize the first path with the ID of the first edge
    first_path_edges = [first_edge["id"]]

    # Follow the first option for egress interfaces until there is no next edge
    next_edge_id = (
        first_edge["nextEdgeIds"][0] if len(first_edge["nextEdgeIds"]) > 0 else None
    )
    prev_next_edge_id = first_edge["id"]
    while next_edge_id is not None:
        if next_edge_id in pathlookup_edges:
            first_path_edges.append(pathlookup_edges[next_edge_id]["id"])
        else:
            # in this situation we can encounter this nextEdgeIds
            # vDevice/913624679@ge-0/0/4.200--dropped--#0
            # we need to add the hostname
            new_nextedge_id = replace_vdevice_id(pathlookup_edges[prev_next_edge_id])
            first_path_edges.append(new_nextedge_id)
        prev_next_edge_id = next_edge_id
        next_edge_id = (
            pathlookup_edges[prev_next_edge_id]["nextEdgeIds"][0]
            if prev_next_edge_id in pathlookup_edges
            and len(pathlookup_edges[prev_next_edge_id]["nextEdgeIds"]) > 0
            else None
        )

    # Build the new Display (ASCII GRAPH)
    # generate_ascii_graph(first_path_edges)
    return first_path_edges


def get_edge_details(
    pathlookup_decisions: dict,
    device: str,
    egress: str,
    neighbor_ingress: str,
    neighbor: str,
    path_id: str,
    zonefw_interfaces=None,
):
    """
    Returns a formatted string with the details of the edge.

    :param pathlookup_decisions: Dictionary containing path decisions
    :param device: Source device of the edge
    :param egress: Egress port of the edge
    :param neighbor_ingress: Ingress port of the neighbor device
    :param neighbor: Neighbor device of the edge
    :param path_id: Id of the current path
    :param zonefw_interfaces: Dictionary containing zone firewall interfaces
    :return: A formatted string with the details of the edge
    """
    def get_security_traces(traces, security_info=""):
        """
        Returns a string with the security event information from the traces.

        :param traces: List containing traces from pathlookup_decisions
        :param security_info: Optional preexisting string with the security event information
        :return: A formatted string with the security event information
        """
        # Loop through each trace in the traces list and extract the security event details
        for trace in traces:
            for trace_detail in trace:
                # Check if any events in the trace contain the word "security"
                for event in trace_detail["events"]:
                    security_info = get_security_event(event, security_info)
                    if security_info:
                        # Exit the loop once a match is found
                        break
                if security_info:
                    break
            if security_info:
                break
        
        return security_info

    def get_security_event(event, security_info=""):
        """
        Returns a formatted string with the security event information from the event dictionary.

        :param event: Dictionary containing the security event information
        :param security_info: Optional preexisting string with the security event information
        :return: A formatted string with the security event information
        """
        # Return the preexisting security info if provided
        if security_info:
            return security_info
        
        # If no preexisting security info provided, construct the security info string
        security_info = ""
        if "security" in event.get("type", ""):
            security_info = f"{event['type']} | {event['decidingPolicyName']} | "
            security_info += f"{display_severity(event['severityInfo']['severity'])}"
            if zonefw_interfaces:
                security_info += find_zonefw_interface(device_name, egress, zonefw_interfaces)

        return security_info

    def get_protocol_traces(traces):
        """
        Returns the first matching headerType or 'n/a' if no matches are found.

        :param traces: A list of traces which contain the event dictionary.
        :return: A formatted string with the protocol event information.
        """
        list_header_type = [event.get("headerType", "") for trace in traces for trace_detail in trace for event in trace_detail["events"]]
        if CHAIN_SWITCHING in [trace_detail["chain"] for trace in traces for trace_detail in trace]:
            # Return "l2" if CHAIN_SWITCHING is found
            return "l2"
        for headerType in EVENT_HEADER_TYPE:
            if headerType in list_header_type:
                # Return the first matching headerType
                return headerType
        # Return "n/a" if no matches are found
        return "n/a"

    def find_zonefw_interface(device: str, interface: str, zonefw_interfaces):
        """
        Searches for the zoneFW for the specified interface and device.

        :param device: Name of the device
        :param interface: Name of the interface
        :param zonefw_interfaces: Dictionary containing zone firewall interfaces
        :return: A string with the zone firewall information, separated by |
        """
        zones = ""
        for intf in zonefw_interfaces:
            if intf["hostname"] == device and intf["intName"] == interface:
                return f" | {'/'.join(intf['zone'])}"
        return ""

    # Extract the device ID and name from the device argument
    device_id = device.split("!")[0] if len(device.split("!")) > 1 else None
    device_name = device.split("!")[1] if len(device.split("!")) > 1 else device

    # If the device ID is not found, return the device name
    if not device_id:
        return device_name

    # Create the target ID for the edge
    if neighbor in STOP_TRACE:
        target_id = f"{device_id}@{egress}--{neighbor}--#0"  # vDevice/932810493@ge-0/0/4.200--dropped--#0
    else:
        target_id = f"{device}@{egress}--{neighbor}@{neighbor_ingress}--{path_id}"
    target_id = target_id.replace("@None","")
    # Get the traces for the device from the pathlookup_decisions data
    traces = [
        trace["trace"]
        for trace in pathlookup_decisions[device_id]["traces"]
        if trace["targetPacketId"] == target_id
    ]

    security_info = ""
    security_info = get_security_traces(traces, security_info)
    protocol_info = get_protocol_traces(traces)
    device_info = f"{device_name} | {protocol_info}"
    if security_info:
        device_info +=  f" | {security_info} |"

    # If no security events are found, return the device name
    return device_info


def display_path(
    path: list,
    details=False,
    pathlookup_decisions=None,
    zonefw_interfaces=None,
    l2_exclusion=False
):
    """
    Builds and displays a graph representation of a given path.

    :param path: Path to display
    :param details: Flag for displaying detailed edge information
    :param pathlookup_decisions: Dictionary containing path decisions
    :param zonefw_interfaces: Dictionary containing zone firewall interfaces
    :param l2_exclusion: Flag to remove L2 info from the path
    """
    # Define a function to remove the entries as per the exclusion
    def remove_exclusion_protocol(graph_list: list, l2_exclusion: bool):
        """
        Removes entries from the graph_list based on the given exclusion criteria.

        :param graph_list: List representing the graph data
        :param l2_exclusion: Flag to remove L2 info from the path
        :return: A modified list with the specified entries removed
        """
        result = []
        exclusion = "l2/fp" if l2_exclusion else ""
        for i, entry in enumerate(graph_list):
            if i > 0 and i < len(graph_list) - 1:
                if (
                    all(protocol not in entry for protocol in L2_EXCLUSION_PROTOCOL)
                    or "security" in entry
                ) and not entry.startswith(" |"):
                    # Add the entry if it doesn't meet the exclusion criteria and is not an interface
                    result.append(entry)
                elif not entry.startswith(" |"):
                    if result[-1] != f"...{exclusion} skipped...":
                        result.append(f"...{exclusion} skipped...")
            else:
                result.append(entry)
                # Add the last entry as is

        return result

    # Define a function to recursively build the graph
    def build_graph(device, path_id="", device_visited=None, graph_list:list=[]):
        """
        Recursively builds a graph representation of a given path.

        :param device: The current device to display
        :param path_id: The id of the current path
        :param device_visited: A dictionary containing visited edges and their count
        :return: A list containing all decisions to display
        """
        # Print the current device with the given prefix
        if not details:
            display_device = remove_vdevice_id(device)
        if device_visited is None:
            device_visited = {}
        if device in device_visited:
            device_visited[device] += 1
        else:
            device_visited[device] = 0
        if device in connections:
            # Get the details of the edge
            (egress, neighbor_ingress, neighbor, id) = (
                connections[device][device_visited[device]]
                if len(connections[device]) > device_visited[device]
                else ("", "", "", "")
            )
            # Display the edge information
            if details:
                display_device = get_edge_details(
                    pathlookup_decisions,
                    device,
                    egress,
                    neighbor_ingress,
                    neighbor,
                    id,
                    zonefw_interfaces,
                )
            graph_list.append(display_device)
            if neighbor in STOP_TRACE:
                # we set the egress to empty to avoid displaying this information, as the packet is not going out
                egress = ""
            if egress and neighbor_ingress:
                # if egress and a neighbor ingress are the same, we won't display twice the info
                if egress == neighbor_ingress:
                    graph_list.append(f" |{egress}")
                else:
                    graph_list.append(f" |{egress}")
                    graph_list.append(f" |{neighbor_ingress}")
            elif egress or neighbor_ingress:
                graph_list.append(f" |{egress or neighbor_ingress}")
            # Recursively build the graph for the neighbor of the current device
            build_graph(device=neighbor, path_id=id, device_visited=device_visited, graph_list=graph_list)
        else:
            # Print the device if it has no further connections in the path
            graph_list.append(device)
        return graph_list

    # Create a dictionary to store the connections in the path
    connections = {}

    # Iterate through each input path and create a dictionary of connections
    for edge in path:
        # Split the string into its components
        components = edge.split("--")
        # Extract the source and destination devices and interfaces
        source_device = (
            components[0].split("@")[0] if "@" in components[0] else components[0]
        )
        source_int = (
            components[0].split("@")[1]
            if "@" in components[0] and len(components[0].split("@")) > 1
            else None
        )
        dest_device = (
            components[1].split("@")[0] if "@" in components[1] else components[1]
        )
        dest_int = (
            components[1].split("@")[1]
            if "@" in components[1] and len(components[1].split("@")) > 1
            else None
        )
        path_id = components[2] if len(components) > 2 else None
        # Add the connection to the dictionary
        if source_device in connections:
            connections[source_device].append(
                (source_int, dest_int, dest_device, path_id)
            )
        else:
            connections[source_device] = [(source_int, dest_int, dest_device, path_id)]

    # Build the graph with the first device in the connections dictionary
    graph_list = []
    if len(connections.keys()) > 0:
        graph_list = build_graph(next(iter(connections.keys())), graph_list)

    if l2_exclusion:
        temp_graph_list = remove_exclusion_protocol(graph_list, l2_exclusion)
        print(temp_graph_list)
    else:
        print(graph_list)