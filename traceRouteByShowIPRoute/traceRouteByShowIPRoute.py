
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
#     'RID1': {'routingTable': {}, 'interfaceList': ()},
#     'RID_N': {'routingTable': {}, 'interfaceList': ()},
# }
# 
ROUTERS = {}

# Global search tree for Interface IP address to Router ID (RID) resolving.
# Stores Interface IP addresses as keys.
# Returns (RID, interfaceID) list.
# Interface IP addresses SHOULD be globally unique across inspected topology.
GLOBAL_INTERFACE_TREE = SubnetTree.SubnetTree()


# Parser for routing table text output.
# Builds internal SubnetTree search tree in 'routeTree' object.
# routeTree key is Network Prefix, value is list of nexthops.
#
# Returns 'router' dictionary object.
# Format:
# 
# router = {
#   'routingTable': routeTree
# }
#
# Compatible with both Cisco IOS(IOS-XE) 'show ip route' 
# and Cisco ASA 'show route' output format.
def parse_show_ip_route_ios_like(showIPRouteOutput):
    router = {}
    routeTree = SubnetTree.SubnetTree()
    interfaceList = []
    # Parse Local and Connected route strings in text.
    connectedAndLocalRoutesFound = False
    for rawRouteString in REGEXP_ROUTE_LOCAL_CONNECTED.finditer(showIPRouteOutput):
        subnet = (
            rawRouteString.group('ipaddress') 
          + convert_netmask_to_prefix_length(
                rawRouteString.group('maskOrPrefixLength')
            )
        )
        interface = rawRouteString.group('interface')
        routeTree[subnet] = ((interface,), rawRouteString.group(0))
        if rawRouteString.group('routeType') == 'L':
            interfaceList.append((interface, subnet,))
        connectedAndLocalRoutesFound = True
    if not connectedAndLocalRoutesFound:
        print('Failed to find routing table entries in given output')
        return None
    # parse static and dynamic route strings in text
    for rawRouteString in REGEXP_ROUTE.finditer(showIPRouteOutput):
        subnet = (
            rawRouteString.group('subnet') 
          + convert_netmask_to_prefix_length(
                rawRouteString.group('maskOrPrefixLength')
            )
        )
        viaPortion =  rawRouteString.group('viaPortion')
        nextHops= []
        if viaPortion.count('via') > 1:
            for line in viaPortion.split('\n'):
                if line:
                    nextHops.append(REGEXP_VIA_PORTION.match(line).group(1))
        else:
            nextHops.append(REGEXP_VIA_PORTION.match(viaPortion).group(1))
        routeTree[subnet] = (nextHops, rawRouteString.group(0))
    router = {
        'routingTable': routeTree,
        'interfaceList': interfaceList,
    }
    return router

# Gets subnet mask or slashed prefix length
# Returns slashed prefix length format for subnet mask case.
# Returns slashed prefix length as is for slashed prefix length case.
# Returns "" for empty input.
def convert_netmask_to_prefix_length(rawMaskOrPrefixLength):
    if not rawMaskOrPrefixLength:
        return ""
    if re.match("^\/\d\d?$", rawMaskOrPrefixLength):
        return rawMaskOrPrefixLength
    if re.match("^\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?$", rawMaskOrPrefixLength):
        return "/" + str(sum([bin(int(x)).count("1") for x in rawMaskOrPrefixLength.split(".")]))
    return ""

# Performs routeTree lookup in passed router object for passed destination subnet.
# Returns list of nexthops.
def route_lookup(destination, router):
    #print router
    if destination in router['routingTable']:
        return router['routingTable'][destination]
    else:
        return (None, None)

# Returns RouterID by Interface IP address which it belongs to.
def get_rid_by_interface_ip(interface_ip):
    if interface_ip in GLOBAL_INTERFACE_TREE:
        return GLOBAL_INTERFACE_TREE[interface_ip][0]

# Check if nexthop points to local interface.
# Valid for Connected and Local route strings.
def nexthop_is_local(nextHop):
    interfaceTypes = ['Eth', 'Fast', 'Gig', 'Ten', 'Port',
                      'Serial', 'Vlan', 'Tunn', 'Loop', 'Null'
    ]
    for type in interfaceTypes:
        if nextHop.startswith(type):
            return True

# Performs recursive path search from source Router ID (RID) to target subnet.
# Returns tupple of path tupples.
# Each path tupple contains a sequence of Router IDs.
# Multiple paths are supported.
def trace_route(sourceRouterID, target, path=[]):
    if not sourceRouterID:
        return [path + [(None, None)]]
    currentRouter = ROUTERS[sourceRouterID]
    nextHop, rawRouteString = route_lookup(target, currentRouter)
    path = path + [(sourceRouterID, rawRouteString)]
    #print nextHop
    paths = []
    if nextHop:
        if nexthop_is_local(nextHop[0]):
            return [path]

        for nh in nextHop:
            nextHopRID = get_rid_by_interface_ip(nh)
            if not nextHopRID in path:
                innerPath = trace_route(nextHopRID, target, path)
                for p in innerPath:
                    paths.append(p)
    else:
        return [path]
    return paths


# Begin execution.

if not os.path.exists(RT_DIRECTORY):
    exit("%s directory does not exist. Check RT_DIRECTORY variable value." % RT_DIRECTORY)

print("Initializing files...")
starttime = time()

# Go through RT_DIRECTORY and parse all .txt files.
# Generate router objects based on parse result if any.
# Populate ROUTERS with those router objects.
# Default key for each router object is FILENAME.
#
for FILENAME in os.listdir(RT_DIRECTORY):
    if FILENAME.endswith('.txt'):
        fileinitstarttime = time()
        with open(os.path.join(RT_DIRECTORY, FILENAME), 'r') as f:
            print 'Opening ', FILENAME
            rawTable = f.read()
            newRouter = parse_show_ip_route_ios_like(rawTable)
            routerID = FILENAME.replace('.txt', '')
            if newRouter:
                ROUTERS[routerID] = newRouter
                if newRouter['interfaceList']:
                    for iface, addr in newRouter['interfaceList']:
                        GLOBAL_INTERFACE_TREE[addr]= (routerID, iface,)
            else:
                print ('Failed to parse ' + FILENAME)
        print FILENAME + " parsing has been completed in %s sec" % ("{:.3f}".format(time() - fileinitstarttime),)
else:
    if not ROUTERS:
        exit ("Could not find any valid .txt files with routing tables in %s directory" % RT_DIRECTORY)
    print "\nAll files have been initialized in %s sec" % ("{:.3f}".format(time() - starttime),)


# Now ready to perform search based on initialized files.
# Ask for Target and perform path search from each router.
# Print all available paths.
#
while True:

    print '\n'
    targetSubnet = raw_input('Enter Target Subnet or Host: ')

    if not targetSubnet:
        continue
    if not REGEXP_INPUT_IPv4.match(targetSubnet.replace(' ', '')):
        print "incorrect input"
        continue

    lookupstarttime = time()
    for rtr in ROUTERS.keys():
        
        subsearchstarttime = time()
        result = trace_route(rtr, targetSubnet)

        if result:
            print "\n"
            print "PATHS TO %s FROM %s" % (targetSubnet, rtr)
            n = 1
            print 'Detailed info:'
            for r in result:
                print "Path %s:" % n
                print [h[0] for h in r]
                for hop in r:
                    print "ROUTER:", hop[0]
                    print "Matched route string: \n", hop[1]
                else:
                    print '\n'
                n+=1
            else:
                print "Path search on %s has been completed in %s sec" % (rtr, "{:.3f}".format(time() - subsearchstarttime))
    else:
        print "\nFull search has been completed in %s sec" % ("{:.3f}".format(time() - lookupstarttime),)













