#!/usr/bin/python

import stl_path
import configparser
import argparse
from trex.stl.api import *
from trex.common.services.trex_service_pppoe import ServicePPPOE
from time import perf_counter, sleep
from functools import partial

from scapy.layers.l2 import Ether
from scapy.layers.ppp import PPP, PPPoE
from json_to_sub import JsonParser
import concurrent.futures
from threading import Thread
from threading import Lock
from queue import Queue
from itertools import repeat
from datetime import datetime, timedelta


wait_for_key = input
lock = Lock()


def random_mac ():
    c = partial(random.randint, 0 ,255)
    return '%02x:%02x:%02x:%02x:%02x:%02x' % (c(), c(), c(), c(), c(), c())
    
def random_mac_range (count):
    return [random_mac() for _ in range(count)]

# generate a packet hook function with PPPoE in PCAP mode
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


class pppoe_http_res():
    def __init__(self, dst_mac, src_mac, sessionid, dst_ip, src_ip, dport, sport, seq, ack):
        self.dst_mac = dst_mac
        self.src_mac = src_mac
        self.sessionid = sessionid
        self.dst_ip = dst_ip
        self.src_ip = src_ip
        self.dport = dport
        self.sport = sport
        self.seq = seq
        self.ack = ack
         

class PPPoETest(object):
    def __init__ (self, port):
        self.port = port
        self.c    = STLClient()
        
    def run(self, config_settings, subscribers):
            
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

            assert len(clients) == config_settings.count
                
            # inject traffic
            self.inject(clients, config_settings)
            
            # teardown - release clients
            self.teardown(clients, config_settings)
            
            
        except STLError as e:
            print(e)
            exit(1)
            
        finally:
            self.c.disconnect()
            

            
    def setup(self, config_settings, subscribers):
            
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
        
    
    def inject(self, clients, config_settings):
        # print('\n\nPress Return to generate high speed traffic from all clients...')
        # wait_for_key()
        
        print('\n*** step 3: generating UDP traffic from {} clients ***\n'.format(len(clients)))
        
        if config_settings.mode == 'BIDIRECT':
            self.c.reset(ports = 0)
            self.c.set_service_mode(ports = self.port, enabled=True)
            self.c.acquire(ports=0, force=True, sync_streams=True)
            self.c.set_port_attr([0], promiscuous = True)

            if config_settings.multithreading == 'true':
                for client in clients:
                    conn = TCP_handshake(client, config_settings, self.c)
                    flow_thread = Thread(target=conn.start_keepalive_flow, args=())
                    flow_thread.start()
            
            else:
                # time_start = perf_counter()
                # jobs = Queue()
                while True:
                    http_streams = []
                    self.c.reset(ports = 0)
                    self.c.set_service_mode(ports = self.port, enabled=True)
                    self.c.acquire(ports=0, force=True, sync_streams=True)
                    self.c.set_port_attr([0], promiscuous = True)

                    # OPEN CONNECTIONS FOR CLIENTS
                    connections = []
                    for client in clients:
                        conn = TCP_handshake(client, config_settings, self.c)
                        connections.append(conn)
                        # jobs.put(conn)
                        conn.start()
                        # conn.send_ack()
                        http = conn.get_http_pkt()


                        http_stream = STLStream(packet=STLPktBuilder(pkt=http), mode=STLTXSingleBurst(pps=1, total_pkts=1))
                        http_streams.append(http_stream)

                    # START HTTP FLOW
                    print(f'CONNECTIONS: {len(connections)}')
                    print('START HTTP FLOW')
                    self.c.set_service_mode(ports = self.port, enabled=False)
                    self.c.add_streams(ports = self.port, streams = http_streams)
                    self.c.start(ports = [0], mult = '100pps')
                    print('STOP HTTP FLOW')

                    print('CLOSE CONNECTIONS')

                    # CAPTURE OK PACKETS
                    self.c.reset(ports = 0)
                    self.c.set_service_mode(ports = self.port, enabled=True)
                    self.c.acquire(ports=0, force=True, sync_streams=True)
                    self.c.set_port_attr([0], promiscuous = True)
                    capture_ok = self.c.start_capture(rx_ports = [0], mode='fixed')
                    rx_pkts = []
                    time.sleep(2)
                    self.c.stop_capture(capture_id = capture_ok['id'], output = rx_pkts)


                    responses = dict()
                    for pkt in rx_pkts:
                        p = Ether(pkt['binary'])
                        if Ether in p:
                            if p[Ether].type == Ether.type.s2i['PPP_SES']:
                                # if p[PPPoE].sessionid == record.sid:
                                if TCP in p:
                                    if p[TCP].flags == 'PA':
                                        res = pppoe_http_res( 
                                                        p[Ether].dst,
                                                        p[Ether].src,
                                                        p[PPPoE].sessionid,
                                                        p[IP].dst,
                                                        p[IP].src,
                                                        p[TCP].dport,
                                                        p[TCP].sport,
                                                        p[TCP].seq,
                                                        p[TCP].ack,
                                                        )
                                        responses[res.dst_mac] = res
                                        # p.show()
                                        # if p[TCP].flags == 'A':
                        #                     syn_ack = p
                    print(f'count responses: {len(responses)}')
                    # SEND FIN
                    #self.c.reset(ports = 0)
                    #self.c.set_service_mode(ports = self.port, enabled=True)
                    for res in responses.values():
                        fin_ack_req =   Ether(src=res.dst_mac,dst=res.src_mac)/ \
                                PPPoE(sessionid=res.sessionid)/ \
                                PPP(proto="Internet Protocol version 4")/ \
                                IP(src=res.dst_ip, dst=res.src_ip)/ \
                                TCP(sport=res.dport, dport=res.sport, flags='FA', seq=res.ack, ack=res.seq+1)
            
                        capture_fin = self.c.start_capture(rx_ports = [0], mode='fixed')
                        self.c.push_packets(ports = [0], pkts = fin_ack_req, force = True)
                        rx_pkts_res = []
                        time.sleep(0.01)
                        self.c.stop_capture(capture_id = capture_fin['id'], output = rx_pkts_res)
                        # print(f'fin_ack {res.dst_ip} sended')

                        # RECIEVE FIN_ACK
                        fin_ack_res = None
                        for pkt in rx_pkts_res:
                            p = Ether(pkt['binary'])
                            if Ether in p:
                                if p[Ether].type == Ether.type.s2i['PPP_SES']:
                                    # if p[PPPoE].sessionid == record.sid:
                                    if TCP in p:
                                        if p[TCP].flags == 'FA':
                                            fin_ack_res = pppoe_http_res(
                                                            p[Ether].dst,
                                                            p[Ether].src,
                                                            p[PPPoE].sessionid,
                                                            p[IP].dst,
                                                            p[IP].src,
                                                            p[TCP].dport,
                                                            p[TCP].sport,
                                                            p[TCP].seq,
                                                            p[TCP].ack,
                                                            )
                                            # print(f'fin_ack {res.dst_ip} recieved')
                                        # p.show()
                                            

                        # SEND ACK
                        if fin_ack_res:
                            ack =   Ether(src=fin_ack_res.dst_mac,dst=fin_ack_res.src_mac)/ \
                                    PPPoE(sessionid=fin_ack_res.sessionid)/ \
                                    PPP(proto="Internet Protocol version 4")/ \
                                    IP(src=fin_ack_res.dst_ip, dst=fin_ack_res.src_ip)/ \
                                    TCP(sport=fin_ack_res.dport, dport=fin_ack_res.sport, flags='A', seq=fin_ack_res.ack, ack=fin_ack_res.seq+1)
                            self.c.push_packets(ports = [0], pkts = ack, force = True)
                            # print(f'ack {res.dst_ip} sended')
                    print('CLOSE CONNECTIONS DONE')
                    sleep(100)

            
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
            self.c.start(ports = [0], mult = '100%', duration=config_settings.duration)

        # self.c.wait_on_traffic(ports=[0,1])
        self.c.wait_on_traffic(ports=[0]) # Use of 1 port
        
        print('\n*** Done ***\n')
        
    def teardown(self, clients, config_settings):
        if config_settings.mode in ('PCAP', 'BIDIRECT'):
            stats = self.c.get_stats()
            opackets = stats[self.port]['opackets']
            print("{0} packets were Tx on port {1}\n".format(opackets, self.port))
        else:
            # print('\n\nPress Return to release all DHCP clients...')
            # wait_for_key()
            
            try:
                # move back to service mode for releasing DHCPs
                self.c.set_service_mode(ports = self.port)
                self.release_dhcp_clients(clients)
                
            finally:
                self.c.set_service_mode(ports = self.port, enabled = False)

        
        
    def create_pppoe_clients(self, config_settings, subscribers):
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
        
class TCP_handshake():

    __estab_conn = 0
    __keepalive_interval = 5
    __keepalive_timeout = 20

    def __init__(self, client, config_settings, STLClient):
        self.seq = 0
        self.ack = 0
        self.keepalive_time = 0
        self.c = STLClient

        self.client = client
        self.server_ip = config_settings.server_ip
        self.last_update = None

    def get_estab_conn(self):
        return TCP_handshake.__estab_conn

    def start(self):
        if self.send_syn():
            self.send_ack()
            return True
        else:
            if not self.send_syn():
                self.send_rst()
                return False
            else:
                self.send_ack()
                return True
        
    def close(self):
        if self.send_fin():
            self.send_ack()
            print(f'CONN CLOSED FOR {self.client.get_record().client_ip}')
        else:
            if not self.send_fin():
                print(f'CONN FOR {self.client.get_record().client_ip} NOT CLOSED')
            else:
                self.send_ack()
                print(f'CONN CLOSED FOR {self.client.get_record().client_ip}')


    def send_syn(self):
        print("SEND_SYN...")
        syn_ack_pkt = None

        record = self.client.get_record()

        syn = Ether(src=record.client_mac,dst=record.server_mac)/ \
                    PPPoE(sessionid=record.sid)/ \
                    PPP(proto="Internet Protocol version 4")/ \
                    IP(src=record.client_ip, dst=self.server_ip)/ \
                    TCP(sport=1024, dport=80, flags='S', seq=self.seq)

        capture_syn = self.c.start_capture(rx_ports = [0], mode='fixed')
        self.c.push_packets(ports = [0], pkts = syn, force = True)
        rx_pkts = []
        time.sleep(0.01)
        self.c.stop_capture(capture_id = capture_syn['id'], output = rx_pkts)

        for pkt in rx_pkts:
            p = Ether(pkt['binary'])
            if Ether in p:
                if p[Ether].type == Ether.type.s2i['PPP_SES']:
                    if p[PPPoE].sessionid == record.sid:
                        if TCP in p:
                            if p[TCP].flags == 'SA':
                                syn_ack_pkt = p
                                self.seq = syn_ack_pkt[TCP].ack
                                self.ack = syn_ack_pkt[TCP].seq+1
                                return True
                                # print(self.seq)
                                # print(self.ack)
                            else:
                                return False


    def send_ack(self):
        record = self.client.get_record()

        if self.seq:
            print(f'SEND_ACK... from {record.client_ip}')


            ack =   Ether(src=record.client_mac,dst=record.server_mac)/ \
                        PPPoE(sessionid=record.sid)/ \
                        PPP(proto="Internet Protocol version 4")/ \
                        IP(src=record.client_ip, dst=self.server_ip)/ \
                        TCP(sport=1024, dport=80, flags='A', seq=self.seq, ack=self.ack)

            self.c.push_packets(ports = [0], pkts = ack, force = True)
            print("SEND_ACK DONE...")
        # else:
        #     #! CLOSE CONNECTION
        #     print(f'NOT ACK FOR {record.client_ip}')

    def send_keepalive_ack(self):
        record = self.client.get_record()

        ack =   Ether(src=record.client_mac,dst=record.server_mac)/ \
                        PPPoE(sessionid=record.sid)/ \
                        PPP(proto="Internet Protocol version 4")/ \
                        IP(src=record.client_ip, dst=self.server_ip)/ \
                        TCP(sport=1024, dport=80, flags='A', seq=self.seq-1, ack=self.ack)

        print(f'SEND_KEEPALIVE... from {record.client_ip}')
        capture_http = self.c.start_capture(rx_ports = [0], mode='fixed')
        self.c.push_packets(ports = [0], pkts = ack, force = True)
        rx_pkts = []
        time.sleep(1)
        self.c.stop_capture(capture_id = capture_http['id'], output = rx_pkts)
        return rx_pkts

    def get_ack_pkt(self):
        ack =   Ether(src=record.client_mac,dst=record.server_mac)/ \
                        PPPoE(sessionid=record.sid)/ \
                        PPP(proto="Internet Protocol version 4")/ \
                        IP(src=record.client_ip, dst=self.server_ip)/ \
                        TCP(sport=1024, dport=80, flags='A', seq=self.seq, ack=self.ack)
        return ack

    def get_http_pkt(self):
        record = self.client.get_record()
        http =  Ether(src=record.client_mac,dst=record.server_mac)/ \
                PPPoE(sessionid=record.sid)/ \
                PPP(proto="Internet Protocol version 4")/ \
                IP(src=record.client_ip, dst=self.server_ip)/ \
                TCP(sport=1024, dport=80, flags='PA', seq=self.seq, ack=self.ack)/ \
                'GET / HTTP/1.1\r\nHost: 192.168.1.10\r\n\r\n'
        return http

    def send_fin(self):
        fin_ack_pkt = None

        record = self.client.get_record()

        fin = Ether(src=record.client_mac,dst=record.server_mac)/ \
                    PPPoE(sessionid=record.sid)/ \
                    PPP(proto="Internet Protocol version 4")/ \
                    IP(src=record.client_ip, dst=self.server_ip)/ \
                    TCP(sport=1024, dport=80, flags='FA', seq=self.seq, ack=self.ack)
        
        capture_fin = self.c.start_capture(rx_ports = [0], mode='fixed')
        self.c.push_packets(ports = [0], pkts = fin, force = True)
        rx_pkts = []
        time.sleep(0.1)
        self.c.stop_capture(capture_id = capture_fin['id'], output = rx_pkts)

        for pkt in rx_pkts:
            p = Ether(pkt['binary'])
            if Ether in p:
                if p[Ether].type == Ether.type.s2i['PPP_SES']:
                    if p[PPPoE].sessionid == record.sid:
                        if TCP in p:
                            if p[TCP].flags == 'FA':
                                fin_ack_pkt = p
                                self.seq = fin_ack_pkt[TCP].ack
                                self.ack = fin_ack_pkt[TCP].seq+1
                                return True
                                # print(self.seq)
                                # print(self.ack)
            # p.show()
            return False
                            # else:
                            #     return False

    def send_rst(self):
        record = self.client.get_record()
        rst = Ether(src=record.client_mac,dst=record.server_mac)/ \
                PPPoE(sessionid=record.sid)/ \
                PPP(proto="Internet Protocol version 4")/ \
                IP(src=record.client_ip, dst=self.server_ip)/ \
                TCP(sport=1024, dport=80, flags='R')

        self.c.push_packets(ports = [0], pkts = rst, force = True)
        print(f'SEND_RST FOR {record.client_ip}')

    def start_keepalive_flow(self):
        if not self.start():
            return
        
        record = self.client.get_record()
        
        self.send_keepalive_ack()
        self.last_update = datetime.now()

        start_time = perf_counter()
        while((perf_counter() - start_time) < TCP_handshake.__keepalive_timeout):
            if ((datetime.now() - timedelta(seconds=TCP_handshake.__keepalive_interval)) > self.last_update):
                
                rx_pkts = self.send_keepalive_ack()

                for pkt in rx_pkts:
                    p = Ether(pkt['binary'])
                    if Ether in p:
                        if p[Ether].type == Ether.type.s2i['PPP_SES']:
                            if p[PPPoE].sessionid == record.sid:
                                if TCP in p:
                                    if p[TCP].flags == 'A':
                                        self.seq = p[TCP].ack
                                        self.ack = p[TCP].seq
                                        self.last_update = datetime.now()
                                        print(f'KEEPALIVE RECIEVED FROM {record.client_ip}')
                                    else:
                                        print(f'KEEPALIVE NOT RECIEVED FROM {record.client_ip}')
                sleep(TCP_handshake.__keepalive_interval)
        self.close()
                

class ConfigSettings:
    def __init__(self, cfg):
        # self.username   = cfg['DEFAULT']['username']
        # self.password   = cfg['DEFAULT']['password']
        self.count      = int(cfg['DEFAULT']['number_of_clients'])
        self.server_ip  = cfg['DEFAULT']['server_ip']
        self.mode       = cfg['DEFAULT']['mode']
        self.payload    = cfg['DEFAULT']['payload']
        if ( int(cfg['DEFAULT']['duration']) > 0 ): 
            self.duration = int(cfg['DEFAULT']['duration']) * 60
        else:
            print('\nERROR: payload duration < 1 min\n')
            exit(1)
        self.pcap_file  = cfg['DEFAULT']['pcap_file']
        self.multithreading = 'true'
    
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--config_path', type=str, required=True)
    args = parser.parse_args()

    # parse jsonfile
    json_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'db/subscribers.json')
    json_parser = JsonParser(json_file)
    subscribers = json_parser.deserialize()
    # parse configfile
    config = configparser.ConfigParser()
    # config_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'cfg/settings.ini')
    config_file = os.path.join(os.path.dirname(os.path.realpath(__file__)), args.config_path)
    config.read(config_file)
    config_settings = ConfigSettings(config)

    pppoe_test = PPPoETest(0)
    pppoe_test.run(config_settings, subscribers)
    
   
if __name__ == '__main__':
    main()

