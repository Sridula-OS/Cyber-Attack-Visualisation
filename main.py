import networkx as nx
import matplotlib.pyplot as plt
from pyvis.network import Network
from pathlib import Path
import webbrowser
import random
import json
from datetime import datetime, timedelta

G = nx.Graph()

flow_durations = {
    # Application
    'HTTP': 0.550,
    'HTTPS': 0.600,
    'DNS': 0.050,
    'SMTP': 0.580,
    'IMAP': 0.650,
    'FTP': 0.520,
    'SSH': 0.700,
    'Telnet': 0.600,
    'RDP': 0.650,
    'DHCP': 0.100,
    'MySQL': 0.520,
    'MongoDB': 0.510,
    'Wi-fi':0.494,
    '802.11':0.494,
    'Bluetooth':0.800
}
# Protocol to server mapping (first 3 -> server1, next 3 -> server2, etc.)
protocol_server_mapping = {
    'HTTP': 'server1', 'HTTPS': 'server1', 'DNS': 'server1',
    'SMTP': 'server2', 'IMAP': 'server2', 'FTP': 'server2',
    'SSH': 'server3', 'Telnet': 'server3', 'RDP': 'server3',
    'DHCP': 'server4', 'MySQL': 'server4', 'MongoDB': 'server4',
    'Wi-fi': 'server5', '802.11': 'server5', 'Bluetooth': 'server5'
}

#ip
ip_count=2
mac_count=0
#mac
def generate_mac_address():
    """Generate a random MAC address"""
    return ":".join([f"{random.randint(0x00, 0xff):02x}" for _ in range(6)])
# Generate 206 unique MAC addresses
mac_addresses = set()
while len(mac_addresses) < 253:
    m=generate_mac_address().upper()
    mac_addresses.add(m)
# Convert to a list and sort (optional)
mac_list = sorted(list(mac_addresses))

#ssh
SSH_BRUTE_FORCE_THRESHOLD = 10  # Attempts per minute to consider as brute force
SSH_ATTACKER_PCS = ["pc42", "pc43", "pc44"]  # Potential attacker PCs
#ssh

# Add 5 servers
for s in range(1,6):
    servers = f"server{s}"
    ipaddress=f"192.168.10.{ip_count}"
    mac=mac_list[mac_count]
    mac_count+=1
    ip_count+=1
    G.add_node(servers, color="#cb9d06",node_type="server",ip_address=ipaddress, mac=mac,degree=0)

# Add 18 routers
for s in range(1,19):
    router = f"router{s}"
    ipaddress=f"192.168.10.{ip_count}"
    mac=mac_list[mac_count]
    mac_count+=1
    ip_count+=1
    G.add_node(router, color="#660033", node_type="router",ip_address=ipaddress,mac=mac,degree=0)
    
cap=83000
switch_router_cap=1000
router_cap=4196
def get_label():
    used = random.randint(0, 50000)
    return f"{used} [{cap}]"

#router1
G.add_edge("router1", "router3", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router1", "router2", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)

#server1
G.add_edge("router1", "server1", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router2", "server1", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router3", "server1", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router5", "server1", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("server2", "server1", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)

#router2
G.add_edge("router2", "server2", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router2", "router4", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)

#server2
G.add_edge("router6", "server2", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router5", "server2", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router7", "server2", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)

#server3
G.add_edge("router7", "server3", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router8", "server3", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router9", "server3", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router3", "router5", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router4", "router6", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router9", "router5", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router6", "router8", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router7", "router8", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router7", "router9", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)

#network2
G.add_edge("router10", "router14", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router11", "router12", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router12", "router13", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router13", "router15", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router15", "router17", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router15", "router10", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router18", "router17", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router13", "router16", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)

for s in range(11, 15):
    sc=f"router{s}"

    G.add_edge(sc, "server4", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)

#connection btw nw1 and nw2
G.add_edge("router2", "server4", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router4", "router14", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)

#server5
G.add_edge("router10", "server5", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router11", "server5", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router15", "server5", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)
G.add_edge("router17", "server5", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=4100000)

# switch 1 Connections
G.add_edge("router1", "switch1", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router2", "switch1", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router5", "switch1", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 2 Connections
G.add_edge("router1", "switch2", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router3", "switch2", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router6", "switch2", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 3 Connections
G.add_edge("router2", "switch3", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router4", "switch3", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router7", "switch3", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 4 Connections
G.add_edge("router3", "switch4", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router5", "switch4", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router8", "switch4", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 5 Connections
G.add_edge("router4", "switch5", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router6", "switch5", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router9", "switch5", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 6 Connections
G.add_edge("router5", "switch6", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router7", "switch6", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router10", "switch6", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 7 Connections
G.add_edge("router6", "switch7", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router8", "switch7", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router11", "switch7", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 8 Connections
G.add_edge("router7", "switch8", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router9", "switch8", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router12", "switch8", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 9 Connections
G.add_edge("router8", "switch9", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router10", "switch9", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router13", "switch9", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 10 Connections
G.add_edge("router9", "switch10", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router11", "switch10", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router14", "switch10", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 11 Connections
G.add_edge("router10", "switch11", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router12", "switch11", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router15", "switch11", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 12 Connections
G.add_edge("router11", "switch12", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router13", "switch12", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router16", "switch12", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 13 Connections
G.add_edge("router12", "switch13", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router14", "switch13", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router17", "switch13", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 14 Connections
G.add_edge("router13", "switch14", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router15", "switch14", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router18", "switch14", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 15 Connections
G.add_edge("router14", "switch15", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router16", "switch15", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router1", "switch15", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 16 Connections
G.add_edge("router15", "switch16", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router17", "switch16", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router2", "switch16", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 17 Connections
G.add_edge("router16", "switch17", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router18", "switch17", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router3", "switch17", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 18 Connections
G.add_edge("router17", "switch18", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router1", "switch18", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router4", "switch18", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 19 Connections
G.add_edge("router18", "switch19", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router2", "switch19", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router5", "switch19", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 20 Connections
G.add_edge("router1", "switch20", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router3", "switch20", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router6", "switch20", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 21 Connections
G.add_edge("router2", "switch21", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router4", "switch21", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router7", "switch21", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 22 Connections
G.add_edge("router3", "switch22", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router5", "switch22", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router8", "switch22", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 23 Connections
G.add_edge("router4", "switch23", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router6", "switch23", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router9", "switch23", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 24 Connections
G.add_edge("router5", "switch24", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router7", "switch24", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router10", "switch24", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

# switch 25 Connections
G.add_edge("router16", "switch25", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router17", "switch25", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)
G.add_edge("router18", "switch25", color="#E0E0E0", label="", weight=0,used=0,flow=0,cap=1000000)

#switches and pcs
pc_count=1
for s in range(1, 26):
    switch = f"switch{s}"
    mac=mac_list[mac_count]
    mac_count+=1
    G.add_node(switch, color="#008080",node_type="switch",mac=mac, degree=0, mitm_attacked=False)
    
    # Add 10 PCs per switch
    j=random.randint(3,10)
    for i in range(1,j+1):
        pc = f"pc{pc_count}"
        ipaddress=f"192.168.10.{ip_count}"
        ip_count+=1
        label = get_label()
        used_part = int(label.split()[0])
        protocol=random.choice(list(flow_durations.keys()))
        if pc in SSH_ATTACKER_PCS:
            protocol = "SSH"
            is_attacker = True
        else:
            protocol = random.choice(list(flow_durations.keys()))
            is_attacker = False
        G.add_node(pc, color="#fffdd0",node_type="pc",protocol=protocol, degree=0,used=used_part,is_ssh_attacker=is_attacker, ssh_attempts=0,ip_address=ipaddress,mac=mac_list[mac_count],ddos_attacker=False)
        flow_42packets=flow_durations[protocol]
        flow=(flow_42packets/42000)*used_part
        G.add_edge(pc, switch, color="#E0E0E0",flow=flow,weight=used_part,used=used_part,cap=83000)
        target_server = protocol_server_mapping.get(protocol, 'server1')
        
        pc_count += 1
        mac_count+=1
        if(pc_count>205):
            break
    if(pc_count>205):
            break
pc_count-=1

def update_edge_usage(G, path, packets_sent):
    #Update 'used' capacity along a path
    for i in range(1,len(path)-1):
        u, v = path[i], path[i+1]
        G[u][v]['weight'] += packets_sent  # Accumulate usage
        ttl_number_of_packets=G[u][v]['weight']
        flow=(0.494/42000) * ttl_number_of_packets
        G[u][v]['flow']=flow
pc_count-=1
def simulate_pc_traffic(G, pc_count):
    for i in range(1,pc_count+1):
        source = f"pc{i}"
        protocol = G.nodes[source].get('protocol', 'HTTP')
        target = protocol_server_mapping.get(protocol)
        try:
            path = nx.dijkstra_path(G, source, target, weight=None)
            print(f"PC{i} ({protocol.upper()}): {path}")
            packets_sent = G.nodes[source]['used']
            update_edge_usage(G,path,packets_sent)    
        except (nx.NetworkXNoPath, KeyError) as e:
            print(f"Routing failed for {source}: {str(e)}")
simulate_pc_traffic(G,pc_count)
#djikstras to simulate traffic initially

#dijikstras
protocol=G.nodes['pc1'].get('protocol')
target_server=protocol_server_mapping.get(protocol)
path = nx.dijkstra_path(G, "pc1",target_server , weight='weight')
path_edges = []
for i in range(len(path) - 1):
    source = path[i]
    target = path[i + 1]
    path_edges.append((source, target))
#dijikstras

#dos
# Configuration Constants
ATTACK_THRESHOLD = 0.8  # Server considers traffic >80% capacity as attack
ATTACK_RATE = 82000      # Packets/second from attacking PC (maxing PC-switch link)
# Global attack state tracker
attack_state = {
    'target_server': None,  # Which server is being attacked
    'attacker_pc': "pc23",    # Which PC is attacking
    'path': []             # Network path the attack takes
}
def simulate_dos_attack(G, attacker_pc="pc23"):
    protocol = G.nodes[attacker_pc].get('protocol')
    target_server = protocol_server_mapping.get(protocol, 'server1')
    try:
        path = nx.shortest_path(G, attacker_pc, target_server, weight='weight')
        path_edges = [(path[i], path[i+1]) for i in range(len(path)-1)]
    except nx.NetworkXNoPath:
        print(f"No path from {attacker_pc} to {target_server}")
        return []
    # 3. Saturate each link along the path with attack traffic
    for u, v in path_edges:
        if G.nodes[u].get('node_type') == 'pc':
            # PC-to-switch link (max 83k packets)
            G[u][v]['weight'] = ATTACK_RATE
        elif G.nodes[u].get('node_type') == 'switch':
            # Switch-to-router link (max 1000k packets)
            G[u][v]['weight'] = max(G[u][v]['weight'] + 81,G[u][v]['weight'])
        else:
            # Router-to-server link (max 4200k packets)
            G[u][v]['weight'] = max(G[u][v]['weight'] + 81, G[u][v]['weight'])
    
    # 4. Initialize attack state
    attack_state.update({
        'target_server': target_server,
        'attacker_pc': attacker_pc,
        'path': path
    })
    return path_edges

def update_attack_visualization(G):
    if not attack_state.get('target_server'):
        return  # No active attack
    
    target = attack_state['target_server']
    path = attack_state['path']
    attacker = attack_state['attacker_pc']
    
    # Immediately mark all affected components
    G.nodes[target]['under_attack'] = True
    
    # Mark all routers in path
    for node in path:
        if G.nodes[node].get('node_type') == 'router':
            G.nodes[node]['under_attack'] = True
    
    # Find and mark the attacker's switch
    attacker_switch = None
    for neighbor in G.neighbors(attacker):
        if G.nodes[neighbor].get('node_type') == 'switch':
            attacker_switch = neighbor
            G.nodes[neighbor]['under_attack'] = True
            break
    
    # Mark the attacker PC
    G.nodes[attacker]['under_attack'] = True
        
simulate_dos_attack(G)
update_attack_visualization(G)
# dos

#ssh
def simulate_ssh_brute_force(G, duration_minutes=5):
    """Simulate SSH brute force attacks from marked attacker PCs"""
    ssh_attack_log = []
    for pc in SSH_ATTACKER_PCS:   
        target_server = 'server3'  # Should be server3 based on your mapping
        attempts = random.randint(30, 120)  # 30-120 attempts in the duration
        # Find path to target server
        try:
            path = nx.shortest_path(G, pc, target_server, weight='weight')
        except nx.NetworkXNoPath:
            continue
        # Record each attempt
        for i in range(attempts):
            attempt_time = datetime.now() - timedelta(minutes=random.uniform(0, duration_minutes))
            success = random.random() < 0.01  # 1% chance of success
            # Log the attempt
            ssh_attack_log.append({
                'timestamp': attempt_time.isoformat(),
                'source': pc,
                'target': target_server,
                'success': success,
                'credentials': f"user{random.randint(1,10)}:pass{random.randint(1000,9999)}"
            })
            # Update graph attributes
            G.nodes[pc]['ssh_attempts'] += 1
            if success:
                G.nodes[pc]['compromised'] = True
                G.nodes[target_server]['compromised'] = True
    return ssh_attack_log

def detect_ssh_brute_force(G, time_window=1, threshold=SSH_BRUTE_FORCE_THRESHOLD):
    """Detect SSH brute force attempts in the network"""
    alerts = []
    current_time = datetime.now()
    for pc in G.nodes():
        if G.nodes[pc].get('is_ssh_attacker', False):
            attempts = G.nodes[pc].get('ssh_attempts', 0)
            if attempts > threshold:
                alert = {
                    'type': 'ssh_brute_force',
                    'source': pc,
                    'target': protocol_server_mapping['SSH'],
                    'attempts': attempts,
                    'timestamp': current_time.isoformat()
                }
                alerts.append(alert)           
    return alerts

ssh_attack_log = simulate_ssh_brute_force(G)
ssh_alerts = detect_ssh_brute_force(G)
#ssh

#ddos
#ddos attack- select 25 pcs 
ddos_attack_pc_list=['pc1','pc2','pc3','pc5','pc7','pc11','pc13','pc17','pc19','pc29','pc31','pc37','pc41','pc43','pc47','pc53','pc59','pc61','pc67','pc71','pc73','pc79','pc83','pc89','pc91']
ddos_attack_paths = {}
for pc in ddos_attack_pc_list:
    if pc in G.nodes:
        # Update node protocol
        G.nodes[pc]['protocol'] = 'HTTP'
        G.nodes[pc]['ddos_attacker'] = True
        G.nodes[pc]['used']=83000
        # Find all edges from this PC
        for neighbor in G.neighbors(pc):
            edge_data = G.get_edge_data(pc, neighbor)
            edge_data['weight'] = 70000  # Set flood traffic    
        path = nx.dijkstra_path(G,pc,'server1', weight=None)
        ddos_attack_paths[pc] = path  # Store path as [pc, ..., server1]
        packets_sent = G.nodes[pc]['used']
        update_edge_usage(G,path,packets_sent)       
# Compute MST from a given node (Prim's algorithm)
bfs_tree = nx.bfs_tree(G, source="server1")
# Convert to JSON-serializable format
tree_data = {
    "nodes": list(bfs_tree.nodes()),
    "edges": list(bfs_tree.edges())
}
#create json file of entire new graph, send all 25 shortest paths as well
#ddos

#mitm
G.nodes['pc86']['protocol'] = 'MySQL'
mitm_path = nx.dijkstra_path(G,'pc86','server4', weight=None)
print(mitm_path)
compromised_switch = None
for node in mitm_path:
    if node.startswith("switch"):
        compromised_switch = node
        break
# Mark the switch as compromised
if compromised_switch:
    G.nodes[compromised_switch]["mitm_attacked"] = True
edge_weight = G.edges['pc86', compromised_switch]['weight']
flow=(0.84/42000) * edge_weight
G.add_edge("pc27", "pc86", color="#000000", label="", weight=edge_weight,flow=flow,cap=54000,hidden=True) #wifi max packet size=2304 bytes, so for 1gbps, max number of packets=54253
G.add_edge("pc27",compromised_switch,color="#000000", label="",weight=edge_weight,flow=flow,cap=54000,hidden=True)
#degree
for node in G.nodes:
    degree_of_node = G.degree(node) 
    G.nodes[node]['degree']=degree_of_node
#degree
#mitm

#data exfiltration
pc = f"pc_exfil"
pc_count += 1
G.add_node(pc, color="#000000",node_type="pc",protocol="DNS", degree=1,used=50000,is_ssh_attacker=False, ssh_attempts=0,ip_address="203.15.10.45",mac=mac_list[mac_count],ddos_attacker=False,hidden=True)
mac_count+=1
flow_42packets=flow_durations[protocol]
flow=(flow_42packets/42000)*used_part
G.add_edge(pc,'pc100', color="#000000",flow=flow,weight=50000,used=50000,cap=54000,hidden=True)
#data exfiltration

#cytoscape
# Convert nodes and edges
cy_nodes = [{"data": {"id": str(node), "label": f"{node}\n{G.nodes[node].get('protocol','')}", "type":G.nodes[node].get("node_type","undefined"), "protocol":G.nodes[node].get("protocol"),"under_attack": G.nodes[node].get("under_attack", False),"ssh_attacker": G.nodes[node].get("is_ssh_attacker", False),
        "ssh_attempts": G.nodes[node].get("ssh_attempts", 0),"compromised": G.nodes[node].get("compromised", False),"ip":G.nodes[node].get("ip_address", ""),"mac":G.nodes[node].get("mac", ""),"used":G.nodes[node].get("used", 0),'ddos_attacker':G.nodes[node].get("ddos_attacker", False),'mitm_attacked':G.nodes[node].get("mitm_attacked", False),"degree": G.nodes[node].get("degree",0),"hidden":G.nodes[node].get('hidden',False)}} for node in G.nodes()]
cy_edges = [{"data": {"source": str(u), "target": str(v),"label": f"Weight: {G[u][v].get('weight', 0)}","cap":G[u][v].get('cap',0),"flow":round(G[u][v].get('flow',0.0),3), "weight":G[u][v].get('weight'),"hidden":G[u][v].get('hidden',False)}
    } for u, v in G.edges()]

attack_path_edges = []
if attack_state['path']:
    path = attack_state['path']
    attack_path_edges = [(path[i], path[i+1]) for i in range(len(path)-1)]

# Combine
cy_elements = {"nodes": cy_nodes, "edges": cy_edges ,"dijikstras":path_edges,"attack_path": attack_path_edges,
        "attack_state": attack_state,"ssh_attacks": ssh_attack_log, "ssh_alerts": ssh_alerts,"ddos_attack_paths":ddos_attack_paths,"bfs_server1":tree_data,"mitm_path":mitm_path}

# Save as JSON
with open("graph_data.json", "w") as f:
    json.dump(cy_elements, f, indent=2)

#cytoscape