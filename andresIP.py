###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################
#Nuevo comentario
import collections
import arp
import syn_flood
import enviar
import dns_spoofing
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from ConfigParser import ConfigParser
import os
import binascii
import socket
import syn_flood_andres



def paqueteIP(pkt, network, IpPuerto,IpMac, Listas, puertoHoneynet):
	srcip = pkt['srcip']
	srcmac = pkt['srcmac']
	switch = pkt['switch']
	inport = pkt['inport']
	dstport = pkt['dstport']

	if srcip in IpMac:
		if IpMac[srcip] == srcmac:
			syn_flood_andres.syn_flood(pkt, network, IpPuerto, IpMac, Listas)
		else:
			comando = "hping3 -1 " + dstport + "-a 192.168.0.1"  
			ping = os.system(comando)
	else:
		IpMac[srcip]=srcmac
		for port in network.topology.egress_locations() - {Location(switch,inport)} - {Location(switch, puertoHoneynet)}:
					puerto = port.port_no
					enviar.enviar_paquete(pkt,network,puerto)

	
		



