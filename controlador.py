###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

import collections
import arp
import enviar
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from ConfigParser import ConfigParser
import os 

class ControladorHoneynet(DynamicPolicy):
	config = ConfigParser()
	config.read("honeynet.cfg") #Se ha creado una instancia de la clase ConfigParser que nos permite  leer un archivo de configuracion
	ListaSolicitudes = []
	ListaAtacantes = []
	ListaClientes = []
	numPing = 0

	print "Ejecutando la aplicacion para el controlador de la Honeynet... "

	def __init__(self):
		print "Se iniciara el constructor de la clase.."
		self.query = packets()
		self.remotes_ip = {}
		self.IpPuerto = {}
		self.query.register_callback(self.paquete)
		self.network = None
		super(ControladorHoneynet,self).__init__(self.query)
		print "Ha terminado la ejecucion del constructor.."

	def set_network(self, network):
		self.network = network
	

	def paquete(self,pkt):
		print "Se ha recibido un nuevo paquete..."
        	switch = pkt['switch']
        	inport = pkt['inport']
        	srcip  = pkt['srcip']
        	srcmac = pkt['srcmac']
        	dstip  = pkt['dstip']
        	dstmac = pkt['dstmac']
        	opcode = pkt['protocol']
		tipoo = pkt['ethtype']

		
		#Se determinara si el paquete recibido, es o no del tipo ARP
		if  tipoo == 2054:
			arp.ejecutarARP(pkt,self.network, self.IpPuerto)

        #Se determinara si el paquete recibido, es o no del tipo IP
		elif tipoo == 2048:
			if opcode == 1:
				#paquete ICMP
				print "Se ha recibido un paquete ICMP"
				ipBcast = "ifconfig eth0 | grep 'Bcast'| cut -d':' -f3 | cut -d' ' -f1"
				broadacas_IP = os.system(ipBcast)
				if broadacas_IP == dstip:
					enviar.enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
				else:
					enviar.enviar_paquete(pkt,self.network,self.IpPuerto[dstip])

			elif opcode == 6:
				#paquete TCP
				print "Se ha recibido un paquete TCP"
				#A continuacion de extrae el payload (paquete original) del pkt OpenFlow
				of_payload = pkt['raw']
				a = of_payload.encode("hex")
				#print of_payload
				b = a[94:96]
				print b
				ipServidor = self.config.get("SYNFLOOD","ipServidor")
				if b == "02":
					size = len(self.ListaSolicitudes)
					tamano = self.config.get("SYNFLOOD","tamano")
					print tamano
					print size
					if size < tamano:
						print "1111111"
						if srcip != ipServidor:
							print "2222222"
							if not srcip in self.ListaSolicitudes:
								print "33333333"
								if not srcip in self.ListaAtacantes:
									print "44444444"
									if not srcip in self.ListaClientes:
										print "555555"
										self.ListaSolicitudes.append(srcip)
										print self.ListaSolicitudes[-1]
										enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
									else:	
										print "66666"
										enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
								else:
									print "77777"
									enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
							else:
								print "88888"
								self.ListaSolicitudes.remove(srcip)
								self.ListaAtacantes.append(srcip)
								enviar_paquete(pkt,self.network,self.IpPuerto[dstip])					
							print b
						else:
							print "99999"
							enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
					else:
						self.ListaAtacantes.append(self.ListaSolicitudes[0])
						del self.ListaSolicitudes[0]
						self.ListaSolicitudes.append(srcip)
				elif b == "10":
					print "10101010"
					if srcip != ipServidor:
						print "12121212"
						if srcip in self.ListaSolicitudes:
							print "13131313"
							enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
							self.ListaSolicitudes.remove(srcip)
							self.ListaClientes.append(srcip)
							print self.ListaClientes[-1]
						elif srcip in self.ListaAtacantes:
							print "1414141414"
			    				enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
							self.ListaAtacantes.remove(srcip)
							self.ListaClientes.append(srcip)
						else:
							print "15151515"
							enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
					else:
						print "16161616"
						enviar_paquete(pkt,self.network,self.IpPuerto[dstip])				
				else:
					print "17171717"
					enviar_paquete(pkt,self.network,self.IpPuerto[dstip])

			else:
				enviar_paquete(pkt,self.network,self.IpPuerto[dstip])

def enviar_paquete(paquete,network,outport):
	"""Construct an arp packet from scratch and send"""
	print "Ejecutando senvio de paquete.."
	rp = Packet()
	rp = paquete
	rp = rp.modify(outport = outport)
	#print rp
	network.inject_packet(rp)

def main():
	#print "Ejecutando main.."
	return ControladorHoneynet()
