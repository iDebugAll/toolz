
import os
import re
import pytricia
from time import time


# Path to directory with routing table files.
# Each routing table MUST be in a separate .txt file.
RT_DIRECTORY = "./routing_tables"

# RegEx template string for IPv4 address matching.
REGEXP_IPv4_STR = (
    r'((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
    + r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
    + r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
    + r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
)

# IPv4 CIDR notation matching in user input.
REGEXP_INPUT_IPv4 = re.compile(r"^" + REGEXP_IPv4_STR + r"(\/\d\d?)?$")

# Local and Connected route strings matching.
REGEXP_ROUTE_LOCAL_CONNECTED = re.compile(
    r'^(?P<routeType>[L|C])\s+'
    + r'((?P<ipaddress>\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)'
    + r'\s?'
    + r'(?P<maskOrPrefixLength>(\/\d\d?)?'
    + r'|(\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)?))'
    + r'\ is\ directly\ connected\,\ '
    + r'(?P<interface>\S+)',
    re.MULTILINE
)

# Static and dynamic route strings matching.
REGEXP_ROUTE = re.compile(
    r'^(\S\S?\*?\s?\S?\S?)'
    + r'\s+'
    + r'((?P<subnet>\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)'
    + r'\s?'
    + r'(?P<maskOrPrefixLength>(\/\d\d?)?'
    + r'|(\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)?))'
    + r'\s*'
    + r'(?P<viaPortion>(?:\n?\s+(\[\d\d?\d?\/\d+\])\s+'
    + r'via\s+(\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)(.*)\n?)+)',
    re.MULTILINE
)

# Route string VIA portion matching.
REGEXP_VIA_PORTION = re.compile(
    r'.*via\s+(\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?).*'
)


# Store for 'router' objects generated from input routing table files.
# Each file is represented by a single 'router' object.
# Router is referenced by Router ID (RID).
# RID is filename by default.
# Format:
#
# ROUTERS = {
#     'RID1': {'routing_table': {}, 'interface_list': ()},
#     'RID_N': {'routing_table': {}, 'interface_list': ()},
# }
#
ROUTERS = {}

# Global search tree for Interface IP address to Router ID (RID) resolving.
# Stores Interface IP addresses as keys.
# Returns (RID, interfaceID) list.
# Interface IP addresses SHOULD be globally unique across the inspected topology.
GLOBAL_INTERFACE_TREE = pytricia.PyTricia()


def parse_show_ip_route_ios_like(raw_routing_table):
    """
    Parser for routing table text output.
    Compatible with both Cisco IOS(IOS-XE) 'show ip route'
    and Cisco ASA 'show route' output format.
    Processes input text file and write into Python data structures.
    Builds internal PyTricia search tree in 'route_tree'.
    Generates local interface list for a router in 'interface_list'
    Returns 'router' dictionary object with parsed data.
    """
    router = {}
    route_tree = pytricia.PyTricia()
    interface_list = []
    # Parse Local and Connected route strings in text.
    for raw_route_string in REGEXP_ROUTE_LOCAL_CONNECTED.finditer(raw_routing_table):
        subnet = (
            raw_route_string.group('ipaddress')
            + convert_netmask_to_prefix_length(
                raw_route_string.group('maskOrPrefixLength')
            )
        )
        interface = raw_route_string.group('interface')
        route_tree[subnet] = ((interface,), raw_route_string.group(0))
        if raw_route_string.group('routeType') == 'L':
            interface_list.append((interface, subnet,))
    if not interface_list:
        print('Failed to find routing table entries in given output')
        return None
    # parse static and dynamic route strings in text
    for raw_route_string in REGEXP_ROUTE.finditer(raw_routing_table):
        subnet = (
            raw_route_string.group('subnet')
            + convert_netmask_to_prefix_length(
                raw_route_string.group('maskOrPrefixLength')
            )
        )
        via_portion = raw_route_string.group('viaPortion')
        next_hops = []
        if via_portion.count('via') > 1:
            for line in via_portion.splitlines():
                if line:
                    next_hops.append(REGEXP_VIA_PORTION.match(line).group(1))
        else:
            next_hops.append(REGEXP_VIA_PORTION.match(via_portion).group(1))
        route_tree[subnet] = (next_hops, raw_route_string.group(0))
    router = {
        'routing_table': route_tree,
        'interface_list': interface_list,
    }
    return router


def parse_text_routing_table(raw_routing_table):
    """
    Parser functions wrapper.
    Add additional parsers for alternative routing table syntaxes here.
    """
    router = parse_show_ip_route_ios_like(raw_routing_table)
    if router:
        return router


def convert_netmask_to_prefix_length(mask_or_pref):
    """
    Gets subnet_mask (XXX.XXX.XXX.XXX) of /prefix_length (/XX).
    For subnet_mask, converts it to /prefix_length and returns the result.
    For /prefix_length, returns as is.
    For empty input, returns "" string.
    """
    if not mask_or_pref:
        return ""
    if re.match(r"^\/\d\d?$", mask_or_pref):
        return mask_or_pref
    if re.match(r"^\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?$",
                mask_or_pref):
        return (
            "/"
            + str(sum([bin(int(x)).count("1") for x in mask_or_pref.split(".")]))
        )
    return ""


def route_lookup(destination, router):
    """
    Performs route_tree lookup in passed router object
    for passed destination subnet.
    Returns list of next_hops with original route strings or (None, None)
    depending on the lookup result.
    """
    if destination in router['routing_table']:
        return router['routing_table'][destination]
    else:
        return (None, None)


def get_rid_by_interface_ip(interface_ip):
    """Returns RouterID by Interface IP address which it belongs to."""
    if interface_ip in GLOBAL_INTERFACE_TREE:
        return GLOBAL_INTERFACE_TREE[interface_ip][0]


def nexthop_is_local(next_hop):
    """
    Check if next-hop points to the local interface.
    Will be True for Connected and Local route strings on Cisco devices.
    """
    interface_types = (
        'Eth', 'Fast', 'Gig', 'Ten', 'Port',
        'Serial', 'Vlan', 'Tunn', 'Loop', 'Null'
    )
    for type in interface_types:
        if next_hop.startswith(type):
            return True


def trace_route(source_router_id, target_ip, path=[]):
    """
    Performs recursive path search from source Router ID (RID) to the target subnet.
    Returns tuple of path tuples.
    Each path tuple contains a sequence of Router IDs with matched route strings.
    Multiple paths are supported.
    """
    if not source_router_id:
        return [path + [(None, None)]]
    current_router = ROUTERS[source_router_id]
    next_hop, raw_route_string = route_lookup(target_ip, current_router)
    path = path + [(source_router_id, raw_route_string)]
    paths = []
    if next_hop:
        if nexthop_is_local(next_hop[0]):
            return [path]
        for nh in next_hop:
            next_hop_rid = get_rid_by_interface_ip(nh)
            if next_hop_rid not in [r[0] for r in path]:
                inner_path = trace_route(next_hop_rid, target_ip, path)
                for p in inner_path:
                    paths.append(p)
            else:
                path = path + [(next_hop_rid+"<<LOOP DETECTED", None)]
                return [path]
    else:
        return [path]
    return paths


def do_parse_directory(rt_directory):
    """
    Go through the specified directory and parse all .txt files.
    Generate router objects based on parse result if any.
    Populate new_routers with those router objects.
    The default key for each router object is FILENAME.
    Return new_routers.
    """
    new_routers = {}
    if not os.path.isdir(rt_directory):
        print(
            "{} directory does not exist.".format(rt_directory)
            + "Check rt_directory variable value."
        )
        return None
    start_time = time()
    print("Initializing files...")
    for FILENAME in os.listdir(rt_directory):
        if FILENAME.endswith('.txt'):
            file_init_start_time = time()
            with open(os.path.join(rt_directory, FILENAME), 'r') as f:
                print('Opening {}'.format(FILENAME))
                raw_table = f.read()
                new_router = parse_text_routing_table(raw_table)
                router_id = FILENAME.replace('.txt', '')
                if new_router:
                    new_routers[router_id] = new_router
                    if new_router['interface_list']:
                        for iface, addr in new_router['interface_list']:
                            GLOBAL_INTERFACE_TREE[addr] = (router_id, iface,)
                else:
                    print('Failed to parse ' + FILENAME)
            print(
                FILENAME
                + " parsing has been completed in {} sec".format(
                    "{:.3f}".format(time() - file_init_start_time)
                )
            )
    else:
        if not new_routers:
            print(
                "Could not find any valid .txt files with routing tables"
                + " in {} directory".format(rt_directory)
            )
        else:
            print(
                "\nAll files have been initialized"
                + " in {} sec".format("{:.3f}".format(time() - start_time))
            )
            return new_routers


def do_user_interactive_search():
    """
    Provides interactive search dialog for users.
    Asks user for target subnet or host in CIDR notation.
    Validates input. Prints error and goes back to start for invalid input.
    Executes path search to given target from each router in global ROUTERS.
    Prints formatted path search results.
    Goes back to start.
    """
    while True:
        print('\n')
        target_subnet = input('Enter Target Subnet or Host: ')
        if not target_subnet:
            continue
        if not REGEXP_INPUT_IPv4.match(target_subnet.replace(' ', '')):
            print("incorrect input")
            continue
        lookup_start_time = time()
        for rtr in ROUTERS.keys():
            subsearch_start_time = time()
            result = trace_route(rtr, target_subnet)
            if result:
                print("\n")
                print("PATHS TO {} FROM {}".format(target_subnet, rtr))
                n = 1
                print('Detailed info:')
                for r in result:
                    print("Path {}:".format(n))
                    print([h[0] for h in r])
                    for hop in r:
                        print("ROUTER: {}".format(hop[0]))
                        print("Matched route string: \n{}".format(hop[1]))
                    else:
                        print('\n')
                    n += 1
                else:
                    print(
                        "Path search on {} has been completed in {} sec".format(
                           rtr, "{:.3f}".format(time() - subsearch_start_time)
                        )
                    )
        else:
            print(
                "\nFull search has been completed in {} sec".format(
                   "{:.3f}".format(time() - lookup_start_time),
                )
            )


def main():
    global ROUTERS
    ROUTERS = do_parse_directory(RT_DIRECTORY)
    if ROUTERS:
        do_user_interactive_search()


if __name__ == "__main__":
    main()
