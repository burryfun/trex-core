#!/usr/bin/python
# TODO: DELETE THIS IMPORT?
from __future__ import print_function

import stl_path
import configparser
from trex.stl.api import *
from trex.common.services.trex_service_pppoe import ServicePPPOE
from time import perf_counter
from functools import partial

from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPP, PPPoE
from json_to_sub import JsonParser
import concurrent.futures
from threading import Lock
from itertools import repeat

wait_for_key = input
lock = Lock()


# TODO: SPLIT PACKETS TO CHUNKS IN BIDIRECT MODE
# """
def chunks(lst, n):
    # Yield successive n-sized chunks from lst.
    for i in range(0, len(lst), n):
        yield lst[i:i + n]
# """

CHUNK_SIZE = 100

def random_mac ():
    c = partial(random.randint, 0 ,255)
    return '%02x:%02x:%02x:%02x:%02x:%02x' % (c(), c(), c(), c(), c(), c())
    
def random_mac_range (count):
    return [random_mac() for _ in range(count)]

# generate a packet hook function with PPPoE 
def packet_hook_generator(mac_src, mac_dst, session_id):

    def packet_hook (packet):
        packet = Ether(packet)
        packet_l3 = packet.payload
        # packet_l3.show()
        packet =    Ether(src=mac_src, dst=mac_dst) / \
                    PPPoE(sessionid=session_id)/ \
                    PPP(proto='Internet Protocol version 4')/ \
                    packet_l3

        return packet.convert_to(Raw).load
        

    return packet_hook

# TODO: Multithreading class
# TODO: Простой способ: разбить на 2 функции, и работать с половиной массива
def TCP_handshake_PPP():
    def run():
        return
    http_streams = _lock
    return


"""
    with concurrent.futures.ThreadPoolExecutor() as executor:
        for i in range(len(success_clients))
        #executor.submit(TCP_handshake(run))
"""


        

class PPPoETest(object):
    def __init__ (self, port):
        self.port = port
        self.c    = STLClient()
        
    def run (self, config_settings, subscribers):
            
        try:
            self.c.connect()
            # self.c.reset(ports = [0,1])
            self.c.reset(ports = [0]) # Use of 1 port
            self.ctx  = self.c.create_service_ctx(port = self.port)
            
            # create clients
            clients = self.setup(config_settings, subscribers)
            if not clients:
                print('\nno clients have sucessfully registered...exiting...\n')
                exit(1)
                
            # inject traffic
            self.inject(clients, config_settings)
            
            # teardown - release clients
            self.teardown(clients, config_settings)
            
            
        except STLError as e:
            print(e)
            exit(1)
            
        finally:
            self.c.disconnect()
            

            
    def setup (self, config_settings, subscribers):
            
        # phase one - service context
        self.c.set_service_mode(ports = self.port)
        
        try:
            # create PPPoE clients
            time_start = perf_counter()
            clients = self.create_pppoe_clients(config_settings, subscribers)
            time_stop = perf_counter()
            diff = time_stop - time_start
            if diff > 60:
                print('     Elapsed time: {0}m {1}s'.format(round( diff/60 ), round( diff % 60 )))
            else:
                print('     Elapsed time: {0}s'.format(round( diff, 2)))
            print('     PPPoE negotiation rate: {0} clients per second'.format( round(len(clients) / diff) ))
            if not clients:
                return
            
            return clients
            
        finally:
            self.c.set_service_mode(ports = self.port, enabled = False)
        
    def TCP_handshake(self, client, config_settings):

        streams = []

        syn_ack = None

        record = client.get_record()

        syn = Ether(src=record.client_mac,dst=record.server_mac)/ \
                    PPPoE(sessionid=record.sid)/ \
                    PPP(proto="Internet Protocol version 4")/ \
                    IP(src=record.client_ip, dst=config_settings.server_ip)/ \
                    TCP(sport=1024, dport=80, flags='S')
        
        capture_syn = self.c.start_capture(rx_ports = [0], mode='fixed')
        self.c.push_packets(ports = [0], pkts = syn, force = True)
        rx_pkts = []
        time.sleep(0.001)
        self.c.stop_capture(capture_id = capture_syn['id'], output = rx_pkts)

        for pkt in rx_pkts:
            p = Ether(pkt['binary'])
            if Ether in p:
                if p[Ether].type == Ether.type.s2i['PPP_SES']:
                    if p[PPPoE].sessionid == record.sid:
                        if TCP in p:
                            if p[TCP].flags == 'SA':
                                syn_ack = p

        # print("SYN_ACK DONE")

        #! СЛОВИТЬ SYN_ACK ДОБАВИТЬ В МАССИВ ack[] http[] и Затем ОТПРАВИТЬ ACK[] http[]
    
        if syn_ack:
            ack =   Ether(src=record.client_mac,dst=record.server_mac)/ \
                    PPPoE(sessionid=record.sid)/ \
                    PPP(proto="Internet Protocol version 4")/ \
                    IP(src=record.client_ip, dst=config_settings.server_ip)/ \
                    TCP(sport=1024, dport=80, flags='A', seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq+1)
            # ack_pkts.append(ack)

            # ack_pkts_split = list(chunks(ack_pkts, CHUNK_SIZE))
            # for chunk in ack_pkts_split:
                # self.c.push_packets(ports = [0], pkts = chunk, force = True)
            # self.c.push_packets(ports = [0], pkts = ack, force = True)
            # TODO: HOST SERVER
            # TODO: KEEP ALIVE PACKET FOR 2'nd THREAD
            http =  Ether(src=record.client_mac,dst=record.server_mac)/ \
                            PPPoE(sessionid=record.sid)/ \
                            PPP(proto="Internet Protocol version 4")/ \
                            IP(src=record.client_ip, dst=config_settings.server_ip)/ \
                            TCP(sport=1024, dport=80, flags='PA', seq=syn_ack[TCP].ack, ack=syn_ack[TCP].seq+1)/ \
                            'GET / HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n'
            
            pkt_ack = STLPktBuilder(pkt = ack, vm = [])
            pkt_http = STLPktBuilder(pkt = http, vm = [])

            ack_stream = STLStream(packet = pkt_ack, mode = STLTXCont(pps = 1))
            http_stream = STLStream(packet = pkt_http, mode = STLTXCont(pps = 1000))
            
            # streams.append(ack_stream)
            # streams.append(http_stream)
            # return streams
            return http_stream



    def inject (self, clients, config_settings):
        print('\n\nPress Return to generate high speed traffic from all clients...')
        wait_for_key()
        
        print('\n*** step 3: generating UDP traffic from {} clients ***\n'.format(len(clients)))
        
        if config_settings.mode == 'BIDIRECT':
            http_streams = []

            self.c.reset(ports = 0)
            self.c.set_service_mode(ports = self.port, enabled=True)
            self.c.acquire(ports=0, force=True, sync_streams=True)
            self.c.set_port_attr([0], promiscuous = True)

            time_start = perf_counter()
            for client in clients:
                connections = self.TCP_handshake(client, config_settings)
                if connections:
                    # http_streams.append(connections)
                    http_streams.append(connections[0])
                    http_streams.append(connections[1])

            # with concurrent.futures.ThreadPoolExecutor() as executor:
            #     # for client in clients:
            #     future_to_streams = {executor.submit(self.TCP_handshake, client, config_settings) : client for client in clients}
            #     for stream in concurrent.futures.as_completed(future_to_streams):
            #         if stream.result() != None:
            #             http_streams.append(stream.result())

            time_stop = perf_counter()
            print(f'Elapsed time {time_stop-time_start}')
            # 1 thread - 28.4s
            # 2 threads - 14.3s
            print('\nPress Return to generate HTTP traffic from {} clients...'.format(len(http_streams)))
            wait_for_key()

            # HTTP FLOW
            self.c.reset(ports=self.port)
            self.c.set_service_mode(ports = self.port, enabled=False)
            self.c.add_streams(ports = self.port, streams = http_streams)
            #! MULTIPLIER = 100 pkts???
            self.c.start(ports = [0], mult = '100pps')

            
        elif config_settings.mode == 'PCAP':
            for client in clients:
                self.c.reset(ports=self.port)
                record = client.get_record()
                self.c.push_pcap(config_settings.pcap_file, 
                                 packet_hook=packet_hook_generator(mac_src=record.client_mac,
                                                                   mac_dst=record.server_mac,
                                                                   session_id=record.sid))
                self.c.wait_on_traffic()
        else:
            streams = []
            if config_settings.mode == 'SINGLE':
                if config_settings.payload == 'UDP':
                    for client in clients:
                        record = client.get_record()

                        base_pkt =  Ether(src=record.client_mac,dst=record.server_mac)/ \
                                    PPPoE(sessionid=record.sid)/ \
                                    PPP(proto="Internet Protocol version 4")/ \
                                    IP(src=record.client_ip,dst=config_settings.server_ip)/ \
                                    UDP(sport=1024, dport=12)

                elif config_settings.payload == 'TCP':
                    for client in clients:
                        record = client.get_record()

                        base_pkt =  Ether(src=record.client_mac,dst=record.server_mac)/ \
                                    PPPoE(sessionid=record.sid)/ \
                                    PPP(proto="Internet Protocol version 4")/ \
                                    IP(src=record.client_ip,dst=config_settings.server_ip)/ \
                                    TCP(sport=1024, dport=80, flags='S')

                pkt = STLPktBuilder(pkt = base_pkt, vm = [])
                streams.append(STLStream(packet = pkt, mode = STLTXCont(pps = 1000)))
            elif config_settings.mode == 'MIX':
                for client in clients:
                    record = client.get_record()

                    base_pkt_1 =    Ether(src=record.client_mac,dst=record.server_mac)/ \
                                    PPPoE(sessionid=record.sid)/ \
                                    PPP(proto="Internet Protocol version 4")/ \
                                    IP(src=record.client_ip,dst=config_settings.server_ip)/ \
                                    UDP(sport=1024, dport=12)
                    
                    base_pkt_2 =    Ether(src=record.client_mac,dst=record.server_mac)/ \
                                    PPPoE(sessionid=record.sid)/ \
                                    PPP(proto="Internet Protocol version 4")/ \
                                    IP(src=record.client_ip,dst=config_settings.server_ip)/ \
                                    TCP(sport=1024, dport=80, flags='S')

                    pkt_1 = STLPktBuilder(pkt = base_pkt_1, vm = [])
                    pkt_2 = STLPktBuilder(pkt = base_pkt_2, vm = [])
                    streams.append(STLStream(packet = pkt_1, mode = STLTXCont(pps = 1000)))
                    streams.append(STLStream(packet = pkt_2, mode = STLTXCont(pps = 1000)))

            self.c.add_streams(ports = self.port, streams = streams)
            self.c.start(ports = [0], mult = '100%')

        # self.c.wait_on_traffic(ports=[0,1])
        self.c.wait_on_traffic(ports=[0]) # Use of 1 port
        
        print('\n*** Done ***\n')
        
    def teardown (self, clients, config_settings):
        # TODO: FIN_ACK FOR BIDIRECT TCP SESSION
        if config_settings.mode in ('PCAP', 'BIDIRECT'):
            stats = self.c.get_stats()
            opackets = stats[self.port]['opackets']
            print("{0} packets were Tx on port {1}\n".format(opackets, self.port))
        else:
            print('\n\nPress Return to release all DHCP clients...')
            wait_for_key()
            
            try:
                # move back to service mode for releasing DHCPs
                self.c.set_service_mode(ports = self.port)
                self.release_dhcp_clients(clients)
                
            finally:
                self.c.set_service_mode(ports = self.port, enabled = False)

        
        
    def create_pppoe_clients (self, config_settings, subscribers):
        pppoe_clients = []
        terminated_clients = set()
        for i in range (config_settings.count):
            # pppoe_clients.append(ServicePPPOE(  mac = random_mac(), 
            #                                     counter = i+1,
            #                                     terminated_clients = terminated_clients,
            #                                     verbose_level = ServicePPPOE.ERROR, 
            #                                     username = config_settings.username, 
            #                                     password = config_settings.password))
            pppoe_clients.append(ServicePPPOE(  mac = subscribers[i].mac, 
                                                counter = i+1,
                                                terminated_clients = terminated_clients,
                                                verbose_level = ServicePPPOE.ERROR, 
                                                username = subscribers[i].username, 
                                                password = subscribers[i].password))
        # execute all the registered services
        print('\n*** step 1: starting PPPoE acquire for {} clients ***\n'.format(len(pppoe_clients)))
        self.ctx.run(pppoe_clients)
        
        # check for terminated clients
        
        #print('\nTerminated clients: {0}'.format(terminated_clients))
        successful_clients = [client for client in pppoe_clients if client.get_mac() not in terminated_clients]

        print('\n*** step 2: PPPoE acquire results ***\n')

        counter = 0
        for client in successful_clients:
            counter += 1
            record = client.get_record()
            #print('#{0} client: MAC {1} - PPPoE: {2}'.format(counter, client.get_mac(), record))
        

        # filter those that succeeded
        bounded_pppoe_clients = [client for client in successful_clients if client.state == 'BOUND']
        print('     Total_clients: {0}'.format(len(bounded_pppoe_clients)))
        
        return bounded_pppoe_clients
        
    def release_dhcp_clients (self, clients):
        print('\n*** step 4: starting PPPoE release for {} clients ***\n'.format(len(clients)))
        self.ctx.run(clients)
        
class TCP_handshake(PPPoETest):
    def __init__(self, client, config_settings):
        self.syn = 0

    def send_ack(self):
        self.a = self.port

class ConfigSettings:
    def __init__(self, cfg):
        # self.username   = cfg['DEFAULT']['username']
        # self.password   = cfg['DEFAULT']['password']
        self.count      = int(cfg['DEFAULT']['number_of_clients'])  
        self.server_ip  = cfg['DEFAULT']['server_ip']
        self.mode       = cfg['DEFAULT']['mode']
        self.payload    = cfg['DEFAULT']['payload']
        self.pcap_file  = cfg['DEFAULT']['pcap_file']
    
def main ():
    # TODO: ADD FILEPATH TO SUBSCRIBERS.JSON (db/subscribers.json)

    # parse jsonfile
    json_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'db/subscribers.json')
    json_parser = JsonParser(json_file)
    subscribers = json_parser.deserialize()
    # parse configfile
    config = configparser.ConfigParser()
    config_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'cfg/settings.ini')
    config.read(config_file)
    config_settings = ConfigSettings(config)


    # username  = config['DEFAULT']['username']
    # password  = config['DEFAULT']['password']
    # count     = int(config['DEFAULT']['number_of_clients'])
    # server_ip = config['DEFAULT']['server_ip']

    pppoe_test = PPPoETest(0)
    pppoe_test.run(config_settings, subscribers)
    
   
if __name__ == '__main__':
    main()

