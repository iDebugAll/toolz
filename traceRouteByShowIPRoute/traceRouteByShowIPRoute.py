
import os
import re
import SubnetTree
from time import time


# Path to directory with routing table files.
# Each routing table MUST be in separate .txt file.
RT_DIRECTORY = "./routing_tables"

# RegEx template string for IPv4 address matching. 
REGEXP_IPv4_STR = (
      '((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
    + '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
    + '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
    + '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?))'
)

# IPv4 CIDR notation matching in user input.
REGEXP_INPUT_IPv4 = re.compile("^" + REGEXP_IPv4_STR + "(\/\d\d?)?$")

# Local and Connected route strings matching.
REGEXP_ROUTE_LOCAL_CONNECTED = re.compile(
     '^(?P<routeType>[L|C])\s+'
    + '((?P<ipaddress>\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)'
    + '\s?'
    + '(?P<maskOrPrefixLength>(\/\d\d?)?'
    + '|(\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)?))'
    + '\ is\ directly\ connected\,\ '
    + '(?P<interface>\S+)',
    re.MULTILINE
)

# Static and dynamic route strings matching.
REGEXP_ROUTE = re.compile(
      '^(\S\S?\*?\s?\S?\S?)'
    + '\s+'
    + '((?P<subnet>\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)'
    + '\s?'
    + '(?P<maskOrPrefixLength>(\/\d\d?)?'
    +'|(\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)?))'
    + '\s*'
    + '(?P<viaPortion>(?:\n?\s+(\[\d\d?\d?\/\d+\])\s+'
    + 'via\s+(\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)(.*)\n?)+)',
    re.MULTILINE
)

# Route string VIA portion matching.
REGEXP_VIA_PORTION = re.compile(
    '.*via\s+(\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?).*'
)


# Store for 'router' objects generated from input routing table files. 
# Each file is represented by single 'router' object.
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
# Interface IP addresses SHOULD be globally unique across inspected topology.
GLOBAL_INTERFACE_TREE = SubnetTree.SubnetTree()


# Parser for routing table text output.
# Builds internal SubnetTree search tree in 'route_tree' object.
# route_tree key is Network Prefix, value is list of next_hops.
#
# Returns 'router' dictionary object.
# Format:
# 
# router = {
#   'routing_table': route_tree
# }
#
# Compatible with both Cisco IOS(IOS-XE) 'show ip route' 
# and Cisco ASA 'show route' output format.
def parse_show_ip_route_ios_like(raw_routing_table):
    router = {}
    route_tree = SubnetTree.SubnetTree()
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
        via_portion =  raw_route_string.group('viaPortion')
        next_hops= []
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

# Gets subnet mask or slashed prefix length
# Returns slashed prefix length format for subnet mask case.
# Returns slashed prefix length as is for slashed prefix length case.
# Returns "" for empty input.
def convert_netmask_to_prefix_length(mask_or_pref):
    if not mask_or_pref:
        return ""
    if re.match("^\/\d\d?$", mask_or_pref):
        return mask_or_pref
    if re.match("^\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?$",
                mask_or_pref):
        return (
            "/"
           + str(sum([bin(int(x)).count("1") for x in mask_or_pref.split(".")]))
        )
    return ""

# Performs route_tree lookup in passed router object for passed destination subnet.
# Returns list of next_hops.
def route_lookup(destination, router):
    if destination in router['routing_table']:
        return router['routing_table'][destination]
    else:
        return (None, None)

# Returns RouterID by Interface IP address which it belongs to.
def get_rid_by_interface_ip(interface_ip):
    if interface_ip in GLOBAL_INTERFACE_TREE:
        return GLOBAL_INTERFACE_TREE[interface_ip][0]

# Check if nexthop points to local interface.
# Valid for Connected and Local route strings.
def nexthop_is_local(next_hop):
    interface_types = ('Eth', 'Fast', 'Gig', 'Ten', 'Port',
                      'Serial', 'Vlan', 'Tunn', 'Loop', 'Null'
    )
    for type in interface_types:
        if next_hop.startswith(type):
            return True

# Performs recursive path search from source Router ID (RID) to target subnet.
# Returns tupple of path tupples.
# Each path tupple contains a sequence of Router IDs.
# Multiple paths are supported.
def trace_route(source_router_id, target_ip, path=[]):
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
            if not next_hop_rid in [r[0] for r in path]:
                innerPath = trace_route(next_hop_rid, target_ip, path)
                for p in innerPath:
                    paths.append(p)
            else:
                path = path + [(next_hop_rid+"<<LOOP DETECTED", None)]
                return [path]
    else:
        return [path]
    return paths


# Go through RT_DIRECTORY and parse all .txt files.
# Generate router objects based on parse result if any.
# Populate ROUTERS with those router objects.
# Default key for each router object is FILENAME.
#
def do_parse_directory(rt_directory):
    new_routers = {}
    if not os.path.isdir(rt_directory):
        print("%s directory does not exist. Check rt_directory variable value." % rt_directory)
        return None
    start_time = time()
    print("Initializing files...")
    for FILENAME in os.listdir(rt_directory):
        if FILENAME.endswith('.txt'):
            file_init_start_time = time()
            with open(os.path.join(rt_directory, FILENAME), 'r') as f:
                print ('Opening ', FILENAME)
                raw_table = f.read()
                new_router = parse_show_ip_route_ios_like(raw_table)
                router_id = FILENAME.replace('.txt', '')
                if new_router:
                    new_routers[router_id] = new_router
                    if new_router['interface_list']:
                        for iface, addr in new_router['interface_list']:
                            GLOBAL_INTERFACE_TREE[addr]= (router_id, iface,)
                else:
                    print ('Failed to parse ' + FILENAME)
            print (FILENAME + " parsing has been completed in %s sec" % (
                   "{:.3f}".format(time() - file_init_start_time),)
            )
    else:
        if not new_routers:
            print ("Could not find any valid .txt files with routing tables in %s directory" % rt_directory)
            print ("\nAll files have been initialized in %s sec" % ("{:.3f}".format(time() - start_time),))
        else:
            return new_routers

def do_user_interactive_search():
    while True:
        print ('\n')
        target_subnet = raw_input('Enter Target Subnet or Host: ')
        if not target_subnet:
            continue
        if not REGEXP_INPUT_IPv4.match(target_subnet.replace(' ', '')):
            print ("incorrect input")
            continue
        lookup_start_time = time()
        for rtr in ROUTERS.keys():
            subsearch_start_time = time()
            result = trace_route(rtr, target_subnet)
            if result:
                print ("\n")
                print ("PATHS TO %s FROM %s" % (target_subnet, rtr))
                n = 1
                print ('Detailed info:')
                for r in result:
                    print ("Path %s:" % n)
                    print ([h[0] for h in r])
                    for hop in r:
                        print ("ROUTER: %s" % hop[0])
                        print ("Matched route string: \n%s" % hop[1])
                    else:
                        print ('\n')
                    n+=1
                else:
                    print ("Path search on %s has been completed in %s sec" % (
                           rtr, "{:.3f}".format(time() - subsearch_start_time))
                    )
        else:
            print ("\nFull search has been completed in %s sec" % (
                   "{:.3f}".format(time() - lookup_start_time),)
            )


# Begin execution.

ROUTERS = do_parse_directory(RT_DIRECTORY)
if not ROUTERS:
    exit()

do_user_interactive_search()
# Now ready to perform search based on initialized files.
# Ask for Target and perform path search from each router.
# Print all available paths.
#














