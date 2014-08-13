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


class ControladorHoneynet(DynamicPolicy):
	config = ConfigParser()
	config.read("honeynet.cfg") #Se ha creado una instancia de la clase ConfigParser que nos permite  leer un archivo de configuracion
	ListaSolicitudes = []
	ListaAtacantes = []
	ListaClientes = []
	ListaRARP = []
	ListaDNS = []
	paqueteARP = Packet()
	identificador = ""
	lenURL = 0
	num = 0
	puertoHoneynet = config.get("PUERTOS","puertoHoneynet")

	print "Ejecutando la aplicacion para el controlador de la Honeynet... "

	def __init__(self):
		print "Se iniciara el constructor de la clase.."
		self.query = packets()
		self.remotes_ip = {}
		self.IpPuerto = {}
		self.IpMac = {}
		self.IpMacAtacante = {}

		self.query.register_callback(self.paquete)
		self.network = None
		super(ControladorHoneynet,self).__init__(self.query)
		print "Ha terminado la ejecucion del constructor.."

	def set_network(self, network):
		self.network = network


	def paquete(self,pkt):

            inport = pkt['inport']
            if self.num < 100:
                if inport != int(self.puertoHoneynet):
                    a = self.network
                    b = int(self.puertoHoneynet)
                    #c = self.num
                    ejecucion(pkt, a,b, self.num)
		    print "se a recibido el paquete numero = " + str(self.num)
            else:
		    a = self.network                    
                    b = 1
                    ejecucion(pkt, a, b, self.num)
		    print "se a recibido el paquete numero = " + str(self.num)

def main():
	#print "Ejecutando main.."
	return ControladorHoneynet()

def ejecucion(pkt, network , puertoHoneynet, num):
            #print "se a recibido el paquete numero = " + str(num)
            try:
		switch = pkt['switch']
            	inport = pkt['inport']
            	tipoo = pkt['ethtype']
            	srcmac = pkt['srcmac']
            	dstmac = pkt['dstmac']
            	opcode = pkt['protocol']
            	dstip = pkt['dstip']
		srcip  = pkt['srcip']
            except:
		print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"

            if  tipoo == 2054:
				print "paquete arp"
				for port in network.topology.egress_locations() - {Location(switch,inport)} - {Location(switch, puertoHoneynet)}:
					puerto = port.port_no
					print "puerto entrada = " + str(inport)
					print "puerto switch = " + str(puerto)
					enviar.enviar_paquete(pkt,network,puerto)
					print "****************************************"
				ControladorHoneynet.num=ControladorHoneynet.num+1

            elif tipoo == 2048:
				print "paquete IP "
				for port in network.topology.egress_locations() - {Location(switch,inport)} - {Location(switch, puertoHoneynet)}:
					puerto = port.port_no
					print "puerto entrada = " + str(inport)
					print "puerto switch = " + str(puerto)
					enviar.enviar_paquete(pkt,network,puerto)
					print "//////////////////////////////////////"
				ControladorHoneynet.num=ControladorHoneynet.num+1
            else:
				print "Paquetes desconocidos "
				for port in network.topology.egress_locations() - {Location(switch,inport)} - {Location(switch, puertoHoneynet)}:
					puerto = port.port_no
					print "puerto entrada = " + str(inport)
					print "puerto switch = " + str(puerto)
					enviar.enviar_paquete(pkt,network,puerto)
					print "???????????????????????????????????????????????"

				num=num+1

