#!/usr/bin/python
from __future__ import print_function

import stl_path
from trex.stl.api import *
from trex.common.services.trex_service_pppoe import ServicePPPOE
from time import perf_counter

from functools import partial

try:
    input = raw_input
except NameError:
    pass

wait_for_key = input
    

def random_mac ():
    c = partial(random.randint, 0 ,255)
    return '%02x:%02x:%02x:%02x:%02x:%02x' % (c(), c(), c(), c(), c(), c())
    
def random_mac_range (count):
    return [random_mac() for _ in range(count)]


class PPPoETest(object):
    def __init__ (self, port):
        self.port = port
        self.c    = STLClient()
        
    def run (self, count, username, password):
            
        try:
            self.c.connect()
            # self.c.reset(ports = [0,1])
            self.c.reset(ports = [0]) # Use of 1 port
            self.ctx  = self.c.create_service_ctx(port = self.port)
            
            # create clients
            clients = self.setup(count, username, password)
            if not clients:
                print('\nno clients have sucessfully registered...exiting...\n')
                exit(1)
                
            # inject traffic
            self.inject(clients)
            
            # teardown - release clients
            self.teardown(clients)
            
            
        except STLError as e:
            print(e)
            exit(1)
            
        finally:
            self.c.disconnect()
            

            
    def setup (self, count, username, password):
            
        # phase one - service context
        self.c.set_service_mode(ports = self.port)
        
        try:
            # create PPPoE clients
            time_start = perf_counter()
            clients = self.create_pppoe_clients(count, username, password)
            time_stop = perf_counter()
            print('     Elapsed time: {0} s'.format(round( time_stop - time_start), 2))
            print('     PPPoE negotiation rate: {0} clients per second'.format( round(len(clients) / (time_stop - time_start)) ))
            if not clients:
                return
            
            return clients
            
        finally:
            self.c.set_service_mode(ports = self.port, enabled = False)
        
            
    def inject (self, clients):
        print('\n\nPress Return to generate high speed traffic from all clients...')
        wait_for_key()
        
        print('\n*** step 4: generating UDP traffic from {} clients ***\n'.format(len(clients)))
            
        streams = []
        for client in clients:
            record = client.get_record()
            base_pkt = Ether(src=record.client_mac,dst=record.server_mac)/PPPoE(sessionid=record.sid)/PPP(proto="Internet Protocol version 4")/IP(src=record.client_ip,dst=record.server_ip)/UDP()
            pkt = STLPktBuilder(pkt = base_pkt, vm = [])
            
            streams.append(STLStream(packet = pkt, mode = STLTXCont(pps = 1000)))
        
        self.c.add_streams(ports = self.port, streams = streams)
        self.c.start(ports = [0], mult = '100%')
        # self.c.wait_on_traffic(ports=[0,1])
        self.c.wait_on_traffic(ports=[0]) # Use of 1 port
        
        print('\n*** Done ***\n')
        
    def teardown (self, clients):
        print('\n\nPress Return to release all DHCP clients...')
        wait_for_key()
        
        try:
            # move back to service mode for releasing DHCPs
            self.c.set_service_mode(ports = self.port)
            self.release_dhcp_clients(clients)
            
        finally:
            self.c.set_service_mode(ports = self.port, enabled = False)

        
        
    def create_pppoe_clients (self, count, username, password):
        # pppoe_clients = [ServicePPPOE(mac = random_mac(), verbose_level = ServicePPPOE.ERROR, username = username, password = password) for _ in range(count)]
        pppoe_clients = []
        terminated_clients = set()
        for i in range (count):
            pppoe_clients.append(ServicePPPOE(  mac = random_mac(), 
                                                counter = i+1,
                                                terminated_clients = terminated_clients,
                                                verbose_level = ServicePPPOE.ERROR, 
                                                username = username, 
                                                password = password))
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
        print('\n*** step 5: starting PPPoE release for {} clients ***\n'.format(len(clients)))
        self.ctx.run(clients)
        
        
    
def main ():

    print('Enter username: ', end='')
    username = input()

    print('Enter password: ', end='')
    password = input()

    print('How many PPPoE clients to create: ', end='')
    count = int(input())

    pppoe_test = PPPoETest(0)
    pppoe_test.run(count, username, password)
    
   
if __name__ == '__main__':
    main()

