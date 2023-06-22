import os
from ipfabric.diagrams import Algorithm, EntryPoint, IPFDiagram, OtherOptions, Unicast
from rich import print
from ipdb import set_trace as debug

GREEN = "0"
BLUE = "10"
AMBER = "20"
RED = "30"
COLOUR_DICT = {"Green": GREEN, "Blue": BLUE, "Amber": AMBER, "Red": RED}

def get_json_pathlookup(
    src_ip: str,
    dst_ip: str,
    protocol: str,
    src_port: str,
    dst_port: str,
    ttl: str,
    fragment_offset: str,
    secured_path: bool,
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
    ipf = IPFDiagram(
        base_url=os.getenv("IPF_URL_DEMO"),
        auth=os.getenv("IPF_TOKEN_DEMO"),
        snapshot_id="12dd8c61-129c-431a-b98b-4c9211571f89",
    )
    uni = Unicast(
        startingPoint=src_ip,
        destinationPoint=dst_ip,
        protocol=protocol,
        srcPorts=src_port,
        dstPorts=dst_port,
        ttl=ttl,
        fragmentOffset=fragment_offset,
        securedPath=secured_path,
    )

    # Call IP Fabric and retrieve the path lookup JSON file
    pathlookup_json = ipf.diagram_json(uni)

    # Close the IPFDiagram object
    ipf.close()

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
                print("".join([" └ ", edge])) if "multiple-egress" in edge else print(edge)
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
    None
    """
    # Start from the first entry in the pathlookup_edges dictionary
    first_edge = next(iter(pathlookup_edges.values()))

    # Initialize the first path with the ID of the first edge
    first_path_edges = [first_edge["id"]]

    # Follow the first option for egress interfaces until there is no next edge
    next_edge_id = first_edge["nextEdgeIds"][0] if len(first_edge["nextEdgeIds"]) > 0 else None
    last_edge_id = first_edge["id"]
    while next_edge_id is not None:
        if next_edge_id in pathlookup_edges:
            first_path_edges.append(pathlookup_edges[next_edge_id]["id"])
        else:
            first_path_edges.append(pathlookup_edges[last_edge_id]["nextEdgeIds"][0])
        last_edge_id = next_edge_id
        next_edge_id = (
            pathlookup_edges[last_edge_id]["nextEdgeIds"][0]
            if last_edge_id in pathlookup_edges
            and len(pathlookup_edges[last_edge_id]["nextEdgeIds"]) > 0
            else None
        )

    # Process and print the first path
    processed_path = []
    for edge in first_path_edges:
        processed_edge = edge.split("--")
        processed_edge = [
            f"{e.split('!')[1]}"
            if "!" in e
            else f"{e.split('@')[1]}"
            if "@" in e
            else e
            for e in processed_edge
        ]
        processed_path.append("--".join(processed_edge))
    # print(processed_path)
    for edge in processed_path:
        print(edge)

    # Build the new Display (ASCII GRAPH)
    # generate_ascii_graph(processed_path)

def generate_ascii_graph(processed_path: list):
    #Define a dictionary to store the connections between devices

    # Define a function to recursively build the ASCII graph
    def build_graph(device, interface=None, prefix='', visited=None, source_interface=None):
        debug()
        if visited is None:
            visited = set()
        if device in visited:
            return
        visited.add(device)
        if interface:
            if source_interface:
                print(prefix[:-1] + '|' + interface + '.' + source_interface)
            else:
                print(prefix[:-1] + '|' + interface)
        print(prefix[:-1] + device)
        if device in connections:
            for neighbor in connections[device]:
                neighbor_int = neighbor[0]
                if neighbor_int is None:
                    neighbor_int = neighbor[1]
                if neighbor_int:
                    if source_interface:
                        build_graph(neighbor[2], interface=neighbor_int, prefix=' ' * 1 + '|', visited=visited, source_interface=source_interface)
                    else:
                        build_graph(neighbor[2], interface=neighbor_int, prefix=' ' * 1 + '|', visited=visited, source_interface=interface)
                else:
                    build_graph(neighbor[2], prefix=' ' * 1 + '|', visited=visited, source_interface=source_interface)


    connections = {}

    # Iterate through each input string
    for edge in processed_path:
        # Split the string into its components
        components = edge.split('--')
        # Extract the source and destination devices and interfaces
        source_device = components[0].split('@')[0] if '@' in components[0] else components[0]
        source_int = components[0].split('@')[1] if '@' in components[0] and len(components[0].split('@')) > 1 else None
        dest_device = components[1].split('@')[0]
        dest_int = components[1].split('@')[1] if '@' in components[1] and len(components[1].split('@')) > 1 else None
        # Add the connection to the dictionary
        if source_device in connections:
            connections[source_device].append((source_int, dest_int, dest_device))
        else:
            connections[source_device] = [(source_int, dest_int, dest_device)]

    if len(connections.keys()) > 0:
        build_graph(next(iter(connections.keys())))
    else:
        print("No graph to build")
