'''

Author: Mohsen Imani
This code simulates our relay selection mechanism. It considers an adversary with certain amount of bandwidth and certain number of clients.
The simulator can be run in a way that it only generates paths without adding the adversarial relays to the network to be able to measure the entropy
or it can add the adversarial relays to compute the compromised rate. The adversary's relays are added based on the defined attack scenarios.
attack == "CLIENT", the attacker targets the client, puts all of his relays in the client's location.
attack == 'DEST' the attacker targets the destination, puts all of his relays in the destination's location.
attack == 'BOTH' the attacker targets both the client and the destination, puts all of his relays in their location.
attack == 'NON-TARGETED', the attacker adds his relays in the random locations in the network.

The simulator first considers a scaled-down Tor network, 30% of Tor network in 2015-10-31-23-00-00-consensus.
It also considers 200 clients that are located in the top countries which using Tor, and in each country the locations are picked based on the population of the cities.
'''

# client-destination targeted simulator

import sys, math, random, urllib2, pickle, sys, re, pygeoip, os
import time, copy
import argparse
import multiprocessing
from multiprocessing import Lock, Process, Queue, current_process, Pool# rawdata = pygeoip.GeoIP('/home/isec/GeoIP-1.4.6/data/GeoLiteCity.dat')
PATH_TO_REQUIREMENTS = '../requirements'
PATH_TO__SAVE = './files'
PATH_TO__DATA =  os.path.join(PATH_TO_REQUIREMENTS,'2015-10-31-23-00-00-consensus')  # './data-2013'
rawdata = pygeoip.GeoIP(os.path.join(PATH_TO_REQUIREMENTS,'GeoIP-datasets/GeoLiteCity.dat'))
ai = pygeoip.GeoIP(os.path.join(PATH_TO_REQUIREMENTS,'GeoIP-datasets/GeoIPASNum.dat'))

#### setting for scalling the weights ############
POWER_EXIT = 3.5
POWER_GUARD = 3.5
POWER_MIDDLE = 4.5
BUCKET = 0.4



def gimme_index(length, s, pprm, Gmin, Smax):
    r = random.random()
    tmp = ((1.0 - math.pow(pprm, s * r)) / (1.0 - math.pow(pprm, s))) * (1.0 - (1.0 - Gmin) * (s / Smax))
    tmp = int(tmp * (length - 1))
    if (tmp <= 0.0): tmp = 0
    return tmp


class country_pop():
    def __init__(self):
        self.coord = []
        self.geocode = ''
        self.pp = 0


def give_me_most_pop():
    dict_of_countries = {}
    requested_cntry = ['US', 'DE', 'FR', 'BR', 'ES', 'IT', 'GB', 'RU', 'JP', 'PL']
    fil = open("cities15000.txt", 'r')
    for line in fil:
        parts = line.split('\t')
        # print parts[4],parts[5],parts[8], parts[14]
        if parts[8].upper() in requested_cntry:
            try:
                if parts[8].upper() not in dict_of_countries:
                    lat = float(parts[4])
                    lon = float(parts[5])
                    pp = float(parts[14])
                    tmp = country_pop()
                    tmp.geocode = parts[8].upper()
                    tmp.pp = pp
                    tmp.coord = [lat, lon]
                    dict_of_countries[parts[8].upper()] = tmp
                else:
                    lat = float(parts[4])
                    lon = float(parts[5])
                    pp = float(parts[14])
                    if (dict_of_countries[parts[8].upper()].pp < pp):
                        dict_of_countries[parts[8].upper()].pp = pp
                        dict_of_countries[parts[8].upper()].coord = [lat, lon]
            except:
                continue
    fil.close()
    return dict_of_countries


def ipquery(ip):
    data = rawdata.record_by_name(ip)
    if (data == None):
        return None
    return data


class country:
    def __init__(self):
        geocode = 'NULL'
        self.coord = []


class node():
    def __init__(self):
        self.ind = 0  # OOPS
        self.bw = 0
        self.w = 0
        self.coord = []
        self.dis = 0
        self.p = 0.0
        self.pm = 0.0
        self.at = 0
        self.geocode = ''
        self.flag = 'm'
        self.ip = ''


def getDistance(a, b):
    lat1 = a[0]
    lat2 = b[0]
    lon1 = a[1]
    lon2 = b[1]
    R = 6371
    p1 = lat1 * 0.0174532925
    p2 = lat2 * 0.0174532925
    dp = (lat2 - lat1) * 0.0174532925
    dl = (lon2 - lon1) * 0.0174532925
    a = math.sin(dp / 2.0) * math.sin(dp / 2.0) + math.cos(p1) * math.cos(p2) * math.sin(dl / 2.0) * math.sin(dl / 2.0)
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    d2 = R * c
    return d2


class path():
    def __init__(self):
        self.gip = 'NULL'
        self.mip = 'NULL'
        self.eip = 'NULL'
        self.dis = 0
        self.gc = 0
        self.ec = 0
        self.mc = 0


##############################################################################################################


def num_to_addr(num):
    '''
    Convert an IPv4 address from its integer representation to a string.
    @param[in] num Address as an integer.
    @returns IPv4 address as a string.
    '''
    return '%d.%d.%d.%d' % ((num >> 24) & 0xff,
                            (num >> 16) & 0xff,
                            (num >> 8) & 0xff,
                            (num & 0xff))

def gimme_asn(asn):
    try:
        s = asn.find('AS') + 2
        e = asn.find(' ')
    except:
        return None
    return asn[s:e]



def gimme_asn_database(asn_):
    #the function give a random IP from a given asn
    csv__ = open( os.path.join(PATH_TO_REQUIREMENTS,'GeoIP-datasets/GeoIPASNum2.csv'),'r')
    csv_t = csv.reader(csv__)
    asn_database = {}
    for row in csv_t:
        asn = gimme_asn(row[2])
        if asn == asn_:
            return num_to_addr(random.randint(int(row[0]), int(row[1])))
    return None


def valid_ases():
    #the function give a the list of ASes that we have IPs for them
    csv__ = open(os.path.join(PATH_TO_REQUIREMENTS,'GeoIP-datasets/GeoIPASNum2.csv'),'r')
    csv_t = csv.reader(csv__)
    asn_database = []
    for row in csv_t:
        asn_database.append(gimme_asn(row[2]))
    return asn_database


def ipquery(ip):
    'Returns the lat and lon for the IP'
    data = rawdata.record_by_name(ip)
    if (data == None):
        return None
    return (float(data['latitude']), float(data['longitude']))


def geoquery(ip):
    'returns the 2 letter country code for the IP'
    data = rawdata.record_by_name(ip)
    if (data == None):
        return None
    return data['country_code']


def get_asn(ip):
    try:
        asn = ai.asn_by_addr(ip)
        if asn is not None:
            asn = asn.split(' ')
            asn = str(asn[0][2:])
            return asn
        else:
            return None
    except:
        return None


def gimme_node_bw(possible):
    ss = sum([i.bw for i in possible])
    r = random.uniform(0.0, ss)
    tmpt = 0.0
    for i in possible:
        tmpt += i.bw
        if (tmpt >= r):
            return i


def gimme_node_d(possible):
    mx = max([i.dis for i in possible])
    pos = []
    for j in possible:
        pos.append(mx - j.dis)
    ss = sum(pos)
    r = random.uniform(0.0, ss)
    tmpt = 0.0
    ind = 0
    for i in range(len(pos)):
        tmpt += pos[i]
        if (tmpt >= r):
            ind = i
            break
    return possible[ind]


def gimme_index(length, s, pprm, Gmin, Smax):
    r = random.random()
    tmp = ((1.0 - math.pow(pprm, s * r)) / (1.0 - math.pow(pprm, s))) * (1.0 - ((1.0 - Gmin) * (s / Smax)))
    tmp = int(tmp * (length - 1))
    if (tmp <= 0.0): tmp = 0
    return tmp


def compute_distances(client,nodes,dest,pnodes, lmb,t) :
    max_d = 0
    max_bw = 0.0
    for i in nodes:
        if (t == "e" ):
            if single_guard == 1:
                myguard = pnodes[0][2]
            else:
                myguard = client
            nodes[i][6] = (1.0 - lmb) * getDistance(myguard, nodes[i][2]) + (lmb) * getDistance(dest, nodes[i][2]) #TODO: fix it
        if (t == "g" ):
            nodes[i][6] = (lmb) * getDistance(client, nodes[i][2]) + (1.0 - lmb) * getDistance(dest, nodes[i][2])
        if (t == "m" ):  # remind that put entry and exit in the place of client and dest
            nodes[i][6] = getDistance(client, nodes[i][2]) + getDistance(dest, nodes[i][2])

        if (max_d < nodes[i][6]):
            max_d = nodes[i][6]
        if (max_bw < nodes[i][1]):
            max_bw = nodes[i][1]

    return max_d,max_bw, nodes






def scale_distances(dist,t):
    if (t == 'e'):
        return math.pow(dist,POWER_EXIT)
    elif (t == 'g'):
        return math.pow(dist,POWER_GUARD)
    elif (t == 'm'):
        return math.pow(dist,POWER_MIDDLE)
    else:
        exit(0)
        return

def compute_weights(nodes,alph, max_d, max_bw, t):

    alpha_ = alph
    if (t == 'g') and False:
        alpha_ = alph - 0.2
        if alpha_ < 0:
            alpha_ = 0.0

    tot_weight = 0.0
    for i in nodes:
        tmp_dist = scale_distances( (1.0 - ((float(nodes[i][6])) / float(max_d))), t)
        nodes[i][5] = (alpha_ * (float(nodes[i][1]) / float(max_bw)) + (1.0 - alpha_) * tmp_dist)
        tot_weight += nodes[i][5]
    return tot_weight, nodes

def pick_guards(single_guard, close_dest, client, guards,
                                                        g_bw, m_bw, e_bw, LAMBDA, ALPHA, BETA, PPARAM, Gmin, Smax, tie):
    if single_guard != 1: return []
    guards = gimme_node_our(client, guards,close_dest,  g_bw, m_bw, e_bw,  LAMBDA, ALPHA, BETA, PPARAM, Gmin, Smax, 'g', [], tie)
    return guards


def gimme_node_our(client, nodes, dest, sum_g_bw, sum_m_bw, sum_e_bw, lmb, alph, s, pprm, Gmin, Smax, t, pnodes, tie):

    # print len(nodes)
    deleted = {}
    if (tie != 'W'):
        for nd in pnodes:
            j = nd[0] # ip
            if j in nodes:
                deleted[j] = nodes[j]
                del nodes[j]
    ##################################################################


    if (tie == 'W'):
        sum_g_bw_ = copy.deepcopy(sum_g_bw)
        sum_m_bw_ = copy.deepcopy(sum_m_bw)
        sum_e_bw_ = copy.deepcopy(sum_e_bw)
        for nd in pnodes:
            j = nd[0] # ip
            if j in nodes:
                deleted[j] = nodes[j]
                sum_g_bw_ -= deleted[j][1]
                sum_m_bw_ -= deleted[j][1]
                sum_e_bw_ -= deleted[j][1]
                del nodes[j]
        sum_bw = None
        if (t == "e"): sum_bw = sum_e_bw_
        if (t == "m"): sum_bw = sum_m_bw_
        if (t == "g"): sum_bw = sum_g_bw_
        nodes_v = nodes.values()
        while True:
            r = random.uniform(0.0, sum_bw)
            tmp = 0
            for i in nodes_v:
                tmp += i[1]
                if (tmp >= r):
                    for k in deleted:
                        nodes[k] = deleted[k]
                    return i
            print "NOTHING??????????"

    ##################################################################
    # updating the distances

    max_d, max_bw, nodes = compute_distances(client,nodes,dest,pnodes, lmb,t) # pnodes here should contain the guard for selecting exit
    tot_weight, nodes = compute_weights(nodes,alph, max_d, max_bw, t)


    ##################################################################
    # Up to here just				 #
    # Dmax and BWmax were found		 #
    #		    NOW GO FOR WEIGHTS 				 #
    ##################################################################

    #nodes_v = nodes.values()
    #nodes_ = sorted(nodes_v, key=lambda node: node[5], reverse=True)


    ############### Select a random number for Index###############
    if (tie == "O"):
        #print "Normal selection"
        while True:
            r = random.uniform(0.0, tot_weight)
            tmp = 0.0
            for i in nodes:
                tmp += nodes[i][5] # weights
                if tmp > r:
                    for k in deleted:
                        nodes[k] = deleted[k]
                    return nodes[i]
            exit(0)


    h = int(math.pow(len(nodes), BUCKET))
    if (tie == "B"):  #alpha should be zero here, choose highbandwidth
        #print "breaking the tie with bandwidth, look alpha should be zero"
        possible = []
        for j in range(h):

            r = random.uniform(0.0, tot_weight)
            tmp = 0.0
            for i in nodes:
                tmp += nodes[i][5]
                if tmp > r:
                    possible.append(nodes[i])
                    break

        assert (len(possible) == h), " we selected less than {0}".format(h)

        maxD = max([i[6] for i in possible])
        new_tot = sum([scale_distances((1.0 - (float(i[6])/float(maxD))), t) for i in possible]) # based on distance
        tmp = 0.0
        r = random.uniform(0.0, new_tot)
        for i in possible:
            tmp += scale_distances((1.0 - (float(i[6])/float(maxD))), t)
            if tmp > r:
                for k in deleted:
                    nodes[k] = deleted[k]
                return i

    if (tie == "D"):  #alpha should be 1 here, choose small distnace
        #print "breaking the tie with bandwidth, look alpha should be zero"
        possible = []
        for j in range(h):

            r = random.uniform(0.0, tot_weight)
            tmp = 0.0
            for i in nodes:
                tmp += nodes[i][5]
                if tmp > r:
                    possible.append(nodes[i])
                    break

        assert (len(possible) == h), " we selected less than {0}".format(h)

        maxbw = max([i[1] for i in possible])
        new_tot = sum([float(i[1])/float(maxbw) for i in possible]) # based on distance
        #new_tot += 0.00001
        tmp = 0.0
        r = random.uniform(0.0, new_tot)
        for i in possible:
            tmp += float(i[1])/float(maxbw)
            if tmp > r:
                for k in deleted:
                    nodes[k] = deleted[k]
                return i



def gimme_close_dest(client_coord, dest_dict):
    tmp = []
    tmp_dist = 9999999999999999
    for i in dest_dict:
        if (tmp_dist > getDistance(client_coord, dest_dict[i])):
            tmp_dist = getDistance(client_coord, dest_dict[i])
            tmp = dest_dict[i]
    return tmp


def adverseries_high(attack, targeted_dest, client, guards_, middles_, exits_, sum_g_bw, sum_m_bw, sum_e_bw, max_g_bw, max_m_bw, max_e_bw,
                     precentage):
    precentage = float(precentage) / float(100)
    assert (attack == "CLIENT" or attack == 'DEST' or attack == 'BOTH' or attack == 'NON-TARGETED')
    adv_bw_e = (precentage / float((1.0 - precentage))) * float(sum_e_bw)
    adv_bw_m = (precentage / float((1.0 - precentage))) * float(sum_m_bw)
    adv_bw_g = (precentage / float((1.0 - precentage))) * float(sum_g_bw)

    adv_be_exit = [i[1] for i in exits_]
    adv_be_middle = [i[1] for i in middles_]
    adv_be_guard = [i[1] for i in guards_]
    coords_middle = [i[2] for i in middles_]

    # print 'adv total bw: ',adv_bw_g, adv_bw_m, adv_bw_e
    adv_e = []
    adv_m = []
    adv_g = []
    while (sum(adv_g) <= adv_bw_g):
        adv_g.append(random.choice(adv_be_guard))
    while (sum(adv_m) <= adv_bw_m):
        adv_m.append(random.choice(adv_be_middle))
    while (sum(adv_e) <= adv_bw_e):
        adv_e.append(random.choice(adv_be_exit))

    tmp = sum(adv_g[0:-1])
    adv_g[-1] = adv_bw_g - tmp

    tmp = sum(adv_m[0:-1])
    adv_m[-1] = adv_bw_m - tmp

    tmp = sum(adv_e[0:-1])
    adv_e[-1] = adv_bw_e - tmp

    # print len(adv_g),len(adv_m), len(adv_e)


    client_coords = client[0]
    client_geo = client[1]

    dest_coords = targeted_dest
    dest_geo = "ATT"


    if attack == "CLIENT":
        dest_coords = client[0]
        dest_geo = client[1]
    elif attack == "DEST":
        client_coords = targeted_dest
        client_geo = "ATT"
    else:
        pass


    guards_ = copy.deepcopy(guards_)
    middles_ = copy.deepcopy(middles_)
    exits_ = copy.deepcopy(exits_)

    exits = {}
    middles = {}
    guards = {}
    #0ip,1bw,2coord, 3geocode, 4at,5w, 6dis
    for i in exits_:
        ip = i[0]
        if i[0] in exits: ip = ip + "+"
        exits[ip] = i

    for i in guards_:
        ip = i[0]
        if i[0] in guards: ip = ip + "+"
        guards[ip] = i

    for i in middles_:
        ip = i[0]
        if i[0] in middles: ip = ip + "+"
        middles[ip] = i

    # Here is the place that I have to take care
    if ENTROPY == 0:
        tmp = 0
        for i in range(len(adv_e)):
            tmp += 1
            name = 'attacker' + str(tmp)
            if (attack == 'NON-TARGETED'):
                dest_coords = random.choice(coords_middle)
                dest_geo = "ATT"
            nd = [name,adv_e[i],dest_coords,dest_geo, 1, None,None]
            exits[name] = nd

        for i in range(len(adv_m)):
            tmp += 1
            name = 'attacker' + str(tmp)
            coord = None
            geocode = None
            coord = random.choice(coords_middle)
            geocode = "ATT"
            nd = [name,adv_m[i],coord,geocode, 1, None,None]
            middles[name] = nd

        for i in range(len(adv_g)):
            tmp += 1
            name = 'attacker' + str(tmp)
            if (attack == 'NON-TARGETED'):
                client_coords = random.choice(coords_middle)
                client_geo = "ATT"

            nd = [name,adv_g[i],client_coords,client_geo, 1, None,None]
            guards[name] = nd

    return guards, middles, exits


##############################################################################################################		
def give_me_path_weighting_function(w,input, output,list_guards, close_dest, client, entrys, middles, exits, dests, sum_g_bw,
                                    sum_m_bw, sum_e_bw, lmb, alph, s, pprm, Gmin, Smax, tie):
    dest = random.choice(dests.values())
    for user in iter(input.get, 'STOP'):
        if single_guard == 1:
            assert (len(list_guards) != 0)

        nexit = gimme_node_our(client, exits, dest, sum_g_bw, sum_m_bw, sum_e_bw, lmb, alph, s, pprm, Gmin, Smax, 'e', list_guards,
                               tie)
        if (single_guard == 1):
            nguard = random.choice(list_guards)
        else:
            nguard = gimme_node_our(client, entrys, close_dest, sum_g_bw, sum_m_bw, sum_e_bw, lmb, alph, s, pprm, Gmin, Smax, 'g',
                                    [nexit], tie)

        #nmiddle = gimme_node_our(nguard[2], middles, nexit[2], sum_g_bw, sum_m_bw, sum_e_bw, lmb, alph, s, pprm, Gmin,
        #                         Smax, 'm', [nguard, nexit], tie)
        compromised = 0.0

        if (nexit[4] == 1 and nguard[4] == 1):
            compromised =1
        outs = (nguard[0],nexit[0],compromised)
        output.put(outs)
    return

##############################################################################################################

def parse_consensus_re(consensus):
    # parse the network consensus files
    try:
        fi = open(consensus,'r')
        content = fi.read()
        fi.close()
        relays = {'relays' : []}
        tmp_relays = {}
        # parse out the nickname, guard flag and bandwidth
        regex2 = re.compile(r'^r\s.*\s(?P<ip>\d*[.]\d*[.]\d*[.]\d*)\s.*\n.*[\n]*s\s(?P<type>.*)\nv\s.*\nw\sBandwidth=(?P<bandwidth>[0-9]+)', re.MULTILINE)
        # Find all the matches in the consenses
        for record in regex2.finditer(content):

            # For each record, create a dictionary object for the relay
            ip = str(record.group('ip'))
            asn = get_asn(ip)
            geo = geoquery(ip)
            coords = ipquery(ip)
            id = random.getrandbits(65)
            if coords == None: continue
            isExit = 0
            isGuard = 0
            type_ = record.group('type')
            if ("Exit" in record.group('type')):
                isExit = 1
            if ("Guard" in record.group('type')): isGuard = 1
            relay = {
                "nickname":ip,
                "ID": id,
                "bandwidth": float(record.group('bandwidth')),
                "coord": coords,
                "geo": geo,
                "asn": asn,
                "valid": None,
                "isExit": isExit,
                "isGuard": isGuard,
                "ip": ip,
                "adversary": 0
            }
            if ip in tmp_relays:
                tmp_relays[ip]['bandwidth'] += relay['bandwidth']
            else:
                tmp_relays[ip] = relay
          # And append it to the master list
        relays['relays']= tmp_relays.values()
        return tmp_relays
    except:
        print "Unable to open: ", consensus
        return {}






def get_relays(scale = 1.0):
    relays = parse_consensus_re(PATH_TO__DATA)
    guards, middles , exits = [],[],[]
    for sample in relays:
        r = random.random()
        if r > scale: continue
        rly = relays[sample]
        nd = [None, None, None, None, None, None, None]#0ip,1bw,2coord, 3geocode, 4at,5w, 6dis
        nd[1] = rly["bandwidth"]
        nd[3] = rly['geo']
        nd[4] = rly['adversary']
        nd[0] = rly['ip']
        nd[2] = rly['coord']
        if rly['isExit'] == 1: exits.append(nd)
        if rly['isGuard'] == 1 and rly['isExit'] == 0:guards.append(nd)
        middles.append(nd)
    total = {}
    total['exit'] = exits
    total['middle'] = middles
    total['guard'] = guards
    return total




parser = argparse.ArgumentParser()
parser.add_argument("-f", "--fraction", type=int, help="the adversary's bandwidth percentage, it should be between 0 and 100 ", default=5)
parser.add_argument("-g", "--guard", type=int, help="number of guards", default=1)
parser.add_argument("-a", "--attack", type=str, help="attack type, it should be be one these values: CLIENT, DEST, BOTH, NON-TARGETED", default="NON-TARGETED")
parser.add_argument("-e", "--entropy", type=int, help="activate if we want to compute the entropy, no adverserail relays are added", default=0)
parser.add_argument("-l", "--lam", type=float, help="the lambda in our design, it should be between 0 and 1", default=0.97)
parser.add_argument("-p", "--alpha", type=float, help="the alpha in our design, it should be between 0 and 1", default=1.0)
parser.add_argument("-w", "--process", type=int, help="the number of processes", default=4)
parser.add_argument("-c", "--circuits", type=int, help="the number of circuits builts per clients", default=3000)

args = parser.parse_args()
adv_perc = args.fraction
single_guard = args.guard
ENTROPY = args.entropy
attack = args.attack





LAMBDA = args.lam
test_methods = [args.alpha]
adv_list = [args.fraction]# adversary's bw
ALPHA = 1.0
PROCESSES = args.process
#### Tune up function setting
BETA = 0
PPARAM = 1.7
Gmin = 1.0
Smax = 20.0


# the number of circuits
NUMBER_OF_CIRC = args.circuits
rotation = 3
dest = {1: [30.6847565983, -71.3429716166], 2: [38.0898852259, -114.12789591], 3: [49.295970166, 7.60486173967],
        4: [41.3444085704, 37.1487240606]}# popular destinations



if ENTROPY == 1:
    #if we want to measure the entropy, lets increase the number of circuits per clients
    adv_list = [0]
    NUMBER_OF_CIRC = 6 * NUMBER_OF_CIRC


print 'We are simulating with adversary who owns {0}% total bw, single guard status is {1} and the attack is {2}, entropy is {3}, total circuits {4} '.format(adv_perc, single_guard, attack,ENTROPY, len(clients)* rotation*NUMBER_OF_CIRC)



if single_guard == 1: print "Guard enabled "
else: print "Guard disabled "

if not os.path.exists("./data"):
    os.makedirs("./data")

# pick the clients' locations
output =  open(os.path.join(PATH_TO_REQUIREMENTS,'clients.info'),'r')
loaded_clients = pickle.load(output)
output.close()

clients = [[client.coord,client.geocode, client.pp] for client in loaded_clients]

#0ip,1bw,2coord, 3geocode, 4at,5w, 6dis
if True:
    # get the relays by parsing consensus
    relays_file = open("relays.dic", "w")
    pickle.dump(get_relays(scale = 0.3333),relays_file)

#load relays, these are scaled relays
relays_file = open('relays.dic','r')
relays = pickle.load(relays_file)
guards_,middles_, exits_ = relays['guard'], relays['middle'],relays['exit']



'''
clients = give_me_most_pop()
clients = clients.values()'''

print "exit: ", len(exits_)
print "middle: ", len(middles_)
print "guard: ", len(guards_)
print "clients: ", len(clients)

exit_asn = {}
guards_asn = {}

for i in exits_:
	exit_asn[get_asn(i[0])] = 1
for i in guards_:
        guards_asn[get_asn(i[0])] = 1

print "asns", len(exit_asn), len(guards_asn)

sum_e_bw = sum([i[1] for i in exits_])  # K_byte
sum_m_bw = sum([i[1] for i in middles_])
sum_g_bw = sum([i[1] for i in guards_])

print sum_g_bw, sum_m_bw,sum_e_bw

max_e_bw = max([i[1] for i in exits_])  # K_byte
max_m_bw = max([i[1] for i in middles_])
max_g_bw = max([i[1] for i in guards_])

'''
for i in middles:
    if (middles[i].at == 1):
        k += 1
print k'''










total = {}
t0 = time.time()
for adv in adv_list:

    # client,entrys,middles,exits,dest,sum_g_bw,sum_m_bw,sum_e_bw,lmb, alph, s,pprm,Gmin,Smax, tie ["D", "B",0.0,0.15,0.1,0.5,0.6,0.9,1.0,"W"]
    method = {}
    for app in test_methods:
        if (app == "W"):# vanilla
            tie = app
        elif (app == "B"): # Bandwidth first for our batching methods
            tie = app
            ALPHA = 1.0
        elif (app == "D"):# distance first for our batching methods
            tie = app
            ALPHA = 0.0
        else:
            tie = "O"
            ALPHA = app
        client_number = 0
        our_clients = {}
        t1 = time.time()
        #from here, start again
        compromised_circ = 0
        for client in clients:
            target = dest[(client_number % 4) + 1]
            guards, middles, exits = adverseries_high(attack,target, client, guards_, middles_, exits_, sum_g_bw, sum_m_bw, sum_e_bw,
                                                      max_g_bw, max_m_bw, max_e_bw, adv)
            e_bw = sum([exits[i][1] for i in exits])  # K_byte
            m_bw = sum([middles[i][1] for i in middles])
            g_bw = sum([guards[i][1] for i in guards])
            cl_tmp = []
            client_number += 1
            close_dest = gimme_close_dest(client[0], dest)
            name = client[1] + str(client_number)
            for mh in range(rotation):
                list_guards = []
                list_guards.append(pick_guards(single_guard, close_dest, client[0], guards,
                                                        g_bw, m_bw, e_bw, LAMBDA, ALPHA, BETA, PPARAM, Gmin, Smax, tie))
                #print "       adv %: ", adv, "  app: ", app, "  client:", name
                '''
                for i in range(NUMBER_OF_CIRC):

                    cl_tmp.append(
                        give_me_path_weighting_function(list_guards, i, close_dest, client[0], guards, middles, exits,
                                                        dst, g_bw, m_bw, e_bw, LAMBDA, ALPHA, BETA, PPARAM, Gmin, Smax, tie))


                '''



                t3 = time.time()
                processes = []
                task_queue = Queue()
                results_queue = multiprocessing.JoinableQueue()
                results = []

                # for l in users:
                #    task_queue.put(l)
                circuits = range(NUMBER_OF_CIRC)
                map(task_queue.put, circuits)
                # print "time to put: ",time.time() - t_t1

                for l in range(PROCESSES):
                    task_queue.put('STOP')
                # print "launch processes"
                step = int(len(circuits) / PROCESSES)
                # users[w*step: (w + 1)*step]
                for w in xrange(PROCESSES):
                    p = Process(target=give_me_path_weighting_function, args=(w, task_queue, results_queue,list_guards, close_dest, client[0], guards, middles, exits,
                                                    dest, g_bw, m_bw, e_bw, LAMBDA, ALPHA, BETA, PPARAM, Gmin, Smax, tie))
                    p.daemon = False
                    processes.append(p)
                    p.start()
                # print "empty the result queue"
                for r in range(NUMBER_OF_CIRC):
                    circ = results_queue.get()
                    results_queue.task_done()
                    if circ[2] == 1:
                        compromised_circ += 1
                    cl_tmp.append(circ)
                    # print "join results_queue"
                results_queue.join()
                task_queue.close()
                results_queue.close()
                t4 = time.time()

                #print "client: {0}, time: {1}, Compromise circuits so far: {2}".format(name,t4 - t3, compromised_circ)
                        #print (sum([i.bw for i in middles_])), sum([middles[i].bw for i in middles])
            if ENTROPY != 1: our_clients[name] = cl_tmp
            if ENTROPY == 1:
                t2 = time.time()
                print "adv %: ", adv, "  app: ", app, " time: ", (t2 - t1) / 3600.0, "client: ", name
                #method[app] = clnts
                out = open('./data/adv_{0}_app_{1}_single-guard_{2}_entropy_{3}_attack_{4}_client_{5}.log'.format(adv,app,single_guard,ENTROPY,attack,name), 'w')
                pickle.dump(cl_tmp, out)
                out.close()


        t2 = time.time()
        print "adv %: ", adv, "  app: ", app, " time: ", (t2 - t1) / 3600.0
        #method[app] = clnts
        out = open('./data/adv_{0}_app_{1}_single-guard_{2}_entropy_{3}_attack_{4}.log'.format(adv,app,single_guard,ENTROPY,attack), 'w')
        pickle.dump(our_clients, out)
        out.close()









