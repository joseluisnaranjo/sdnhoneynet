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
import Sync_Flood
import enviar
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from ConfigParser import ConfigParser
import os 
import time

class ControladorHoneynet(DynamicPolicy):
	config = ConfigParser()
	config.read("honeynet.cfg") #Se ha creado una instancia de la clase ConfigParser que nos permite  leer un archivo de configuracion
	ListaSolicitudes = []
	ListaAtacantes = []
	ListaClientes = []
	ListaRARP = []
	

	print "Ejecutando la aplicacion para el controlador de la Honeynet... "

	def __init__(self):
		print "Se iniciara el constructor de la clase.."
		self.query = packets()
		self.remotes_ip = {}
		self.IpPuerto = {}
		self.IpMac = {}
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
			arp.ejecutarARP(pkt,self.network, self.IpPuerto, self.IpMac)

        	#Se determinara si el paquete recibido, es o no del tipo IP
		elif tipoo == 2048:
			#A continuacion se hace una comprobacion de la ip y el puerto de origen con los datos obtenidos al hacer el ARP 
			if self.IpMac[srcip] == srcmac && self.IpPuerto[srcip]==inport:

				if opcode == 1:
					#paquete ICMP
					print "Se ha recibido un paquete ICMP"
					#con el comando ping y un grep vamos a obtener la direccion de broadcasr del interface de red
					ipBcast = "ifconfig eth0 | grep 'Bcast'| cut -d':' -f3 | cut -d' ' -f1"
					broadacast_IP = os.system(ipBcast)
					#se hace una comparacion con la direccion de destino si es la de broadcast para decidir a donde enviar el paquete 
					if broadacast_IP == dstip:
						#destino la honeynet
						enviar.enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
					else:
						#destino la red real
						enviar.enviar_paquete(pkt,self.network,self.IpPuerto[dstip])

				elif opcode == 6:
					#paquete TCP
					Sync_Flood.Sync_Flood(pkt,self.network, self.IpPuerto)

				else:
					#Cualquier otro tipo de paquete que se recibano no se analiza en este proyecto por lo que se envia el paquete sin niguna restriccion.
					enviar.enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
				print "Ver si se envia al puerto de la honeynet" 
			else:
				enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
		
		#Se determinara si el paquete recibido, es o no del tipo RARP
		elif tipoo == 32821:
			#paquete RARP
			self.ListaRARP.append(pkt)
			tiempo = self.config.get("RARP","tiempo")
			time.sleep(tiempo)
			if  len(self.ListaRARP) == 2
				num = 0
				while (num < 2): 
					if self.ListaRARP[num]['srcmac'] != self.IpMac[srcip]
						enviar.enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
						num = num + 1
			else:
				IpMac[srcip] = srcmac
				

def main():
	#print "Ejecutando main.."
	return ControladorHoneynet()
