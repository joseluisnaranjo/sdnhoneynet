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
	puertoHoneynet = config.get("PUERTOS","puertoHoneynet")

	print "Ejecutando la aplicacion para el controlador de la Honeynet... "

	def __init__(self):

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
		print "Se ha recibido un nuevo paquete..."
		try:
			switch = pkt['switch']
			inport = pkt['inport']
			srcmac = pkt['srcmac']
			dstmac = pkt['dstmac']
			tipoo = pkt['ethtype']
			opcode = pkt['protocol']
			srcip  = pkt['srcip']
			dstip = pkt['dstip']
		except:
			print "%%%%%%%%%%%%%%%%%%%%%%%%%%"
			
		
		#Se determinara si el paquete recibido, es o no del tipo ARP"
		if  tipoo == 2054:
			print "paquete ARP "
			arp.ejecutarARP(pkt,self.network, self.IpPuerto, self.IpMac, self.paqueteARP, self.IpMacAtacante)
			
		#Se determinara si el paquete recibido, es o no del tipo IP"
		elif tipoo == 2048:
			print "paquete IP "
			try:
				#A continuacion se hace una comprobacion de la ip y el puerto de origen con los datos obtenidos al hacer el ARP
				#El siguiente lazo if comprueba si se trata de un ip spoofing" 
 
				if ((self.IpMac[srcip] == srcmac) and (self.IpPuerto[srcip]==inport)):
					print "NO se trata de un IP SPOOFING"
					if opcode == 1:
						print "Paquete ICMP"
						
						#con el comando ping y un grep vamos a obtener la direccion de broadcasr del interface de red
						ipBcast = "ifconfig eth0 | grep 'Bcast'| cut -d':' -f3 | cut -d' ' -f1"
						broadcast_IP = os.system(ipBcast)
						#Se hace una comparacion con la direccion de destino si es la de broadcast para decidir a donde enviar el paquete 
						#El siguiente lazo if comprueba si se trata de un ataque smurf
						print broadcast_IP
						if broadcast_IP == dstip:
							#Destino la honeynet
							enviar.enviar_paquete(pkt,self.network,int(self.puertoHoneynet))
							print "ATAQUE SMURF"
						else:
							#Destino la red real
							enviar.enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
							print "BUENO"

					elif opcode == 6:
						print "Paquete TCP"
						syn_flood.syn_flood(pkt,self.network, self.IpPuerto, self.ListaAtacantes, self.ListaClientes, self.ListaSolicitudes)
					
					# Si corresponde a un paquete UDP
					elif opcode == 17:
						print "paquete UDP "
						#A continuacion de extrae el payload codificado (paquete original) del pkt OpenFlow
						of_payload_code = pkt['raw']
						#A continucaion se codifica en hexadecimal dicho payload
						of_payload = of_payload_code.encode("hex")
						#A continuacion se  extrae alguas bandetas de TCP, aquellas que nos indican si es syn, syn-ack y ack 
						dstport = of_payload[74:78]
						if (dstport == 0053):
							dns_spoofing.dns_spoofing(pkt, self.network, self.IpPuerto, self.identificador, self.lenURL, self.ListaDNS)
						else:		
							enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
							
							
							
					else:
						print "Otro tipo de paquete IP"
						#Cualquier otro tipo de paquete que se reciba no se analiza en este proyecto por lo que se envia el paquete sin niguna restriccion.
						enviar.enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
					 
				else:
					print "Se trata de un IP SPOOFING"
					enviar_paquete(pkt,self.network,int(self.puertoHoneynet))
				

			except:	
				print "Error con el paquete IP recibido...(diccionarios vacios)"
				enviar.enviar_ARP(pkt, self.network)
						
			
			
		
		#Se determinara si el paquete recibido, es o no del tipo RARP
		elif tipoo == 32821:
			print "paquete RARP "
			#Lista en el que se guardaran todas las respuestas RARP
			self.ListaRARP.append(pkt)
			#Tiempo que esperara a que lleguen todas las respuestas RARP
			tiempo = self.config.get("RARP","tiempo")
			time.sleep(tiempo)
			
			#A continuacion se comprobara si es que llega mas de una respuesta
			longLista = len(self.ListaRARP)
			if  longLista >= 2:
				num = 0
				while (num < longLista):
					#En la lista de las respuestas RARP buscamos cual es el atacante para enviarlo a la honeynet
					if self.ListaRARP[num]['srcmac'] != self.IpMac[srcip]:
						self.IpMacAtacante[srcip] = srcmac
						self.IpMac.remove(srcip)
						enviar.enviar_paquete(paqueteARP,self.network,self.IpPuerto[dstip])
					num = num + 1
			#Si solo llega una respuesta actualizamos el diccionario IpMac y enviamos el paquete original a que se realice el ARP			
			else:

				arp.ejecutarARP(paqueteARP,self.network, self.IpPuerto, self.IpMac, self.paqueteARP)
				




def main():
	#print "Ejecutando main.."
	return ControladorHoneynet()
