import socket
from socket import setdefaulttimeout
import ipaddress
import itertools
import json
from multiprocessing.pool import ThreadPool
import subprocess
import argparse
import base64
import os

class IPScan():
    def __init__(self):
        setdefaulttimeout(0.25)
        self.open_ports = []
        self.ports = list(range(0,1000)) 

    def scan_single_ip(self, ip):
        return self._host(ipaddress.IPv4Address(ip))
    def scan_range_of_ip(self, start_ip, end_ip):
        start_ip = ipaddress.IPv4Address(start_ip)
        end_ip = ipaddress.IPv4Address(end_ip)
        results = []
        for ip in range(int(start_ip), int(end_ip)):
            results.append(self._host(ipaddress.IPv4Address(ip)))
        return results
    def network(self, network_expression):
        """iterate scan through ip network"""
        results = []
        for ip in ipaddress.IPv4Network(network_expression):
            ip = str(ip)
            results.append(self._host(ip))
        return results

    def port(self, ip, port):
        """scan ports for an ip, result is the connection result, 0 indicates success"""
        try:
            sock = socket.socket()
            sock.settimeout(0.25)
            result = sock.connect_ex((ip, port))
            try:
                if result == 0:
                    self.open_ports.append("port {0}: open".format(str(port)))
                else:
                    self.open_ports.append("port {0}: closed".format(str(port)))
            except Exception as e:
                self.open_ports.append("port {0} conn fail: {1}".format(str(port), e))
            finally:
                sock.close()
        except:
            self.open_ports.append("networking failed for port {0} : {1}".format(str(port), e))

    def _host(self, ip):
        """iterate scan through min and max ports for single ip"""
        _host_temp = str(ip)
        returns = {}
        returns['_hostname'] = socket.getfqdn(_host_temp)
        returns['ipAddress'] = _host_temp
        self.threads = []
        pool = ThreadPool(10) 
        results = pool.starmap(self.port, zip(itertools.repeat(_host_temp), self.ports))
        pool.close() 
        pool.join()
        self.open_ports.sort()
        returns['openPorts'] = self.open_ports
        return returns
