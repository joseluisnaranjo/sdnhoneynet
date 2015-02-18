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
	ListaDNS = []
	paqueteARP = Packet()
	identificador = ""
	lenURL = 0
	

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
		print "Se ha recibido un nuevo paquete..."
        switch = pkt['switch']
     	inport = pkt['inport']
     	srcip  = pkt['srcip']
        srcmac = pkt['srcmac']
        dstip  = pkt['dstip']
        dstmac = pkt['dstmac']
        opcode = pkt['protocol']
		tipoo = pkt['ethtype']
		dstport = pkt ['dstport']

		
		#Se determinara si el paquete recibido, es o no del tipo ARP
		if  tipoo == 2054:
			arp.ejecutarARP(pkt,self.network, self.IpPuerto, self.IpMac, self.paqueteARP, self.IpMacAtacante)

        	#Se determinara si el paquete recibido, es o no del tipo IP
		elif tipoo == 2048:
			#A continuacion se hace una comprobacion de la ip y el puerto de origen con los datos obtenidos al hacer el ARP 
			if ((self.IpMac[srcip] == srcmac) and (self.IpPuerto[srcip]==inport)):

				if opcode == 1:
					#Paquete ICMP
					print "Se ha recibido un paquete ICMP"
					#con el comando ping y un grep vamos a obtener la direccion de broadcasr del interface de red
					ipBcast = "ifconfig eth0 | grep 'Bcast'| cut -d':' -f3 | cut -d' ' -f1"
					broadacast_IP = os.system(ipBcast)
					#Se hace una comparacion con la direccion de destino si es la de broadcast para decidir a donde enviar el paquete 
					if broadacast_IP == dstip:
						#Destino la honeynet
						enviar.enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
					else:
						#Destino la red real
						enviar.enviar_paquete(pkt,self.network,self.IpPuerto[dstip])

				elif opcode == 6:
					#Paquete TCP
					syn_flood.syn_flood(pkt,self.network, self.IpPuerto)
					
					
					
				elif ((opcode == 17) and (dstport == 53)):
					ipServidorDNS = config.get("DNS_Spoofing","ipServidorDNS")
					dns_flags=payload(90,94)
					#Se comprueba si es una pregunta dns al comprobar el contenido de su bandera
					if (dns_flags == 0100):
						if (dstip == ipServidorDNS):
							enviar.enviar_paquete(pkt,set_network,self.IpPuerto[dstip])
							
						else:
							enviar.enviar_paquete(pkt,set_network,self.IpPuerto[dstip])
							enviar.enviar_DNS(pkt,self.network)
							self.identificador=payload(86,88)
							self.lenURL = len(payload(,))
					#En caso de que sea una respuesta, que ip corresponde al dominio preguntado
					elif (dns_flags == 8180):
						idRespuestas = payload(86,88)
						if (idRespuestas == self.identificador):
							#Lista en el que se guardaran todas las respuestas DNS
							self.ListaDNS.append(pkt)
							#Tiempo que esperara a que lleguen todas las respuestas DNS
							tiempo = self.config.get("DNS_Spoofing","tiempo")
							time.sleep(tiempo)
							num = 0
							while (num < 2):
								#A continuacion se  extrae la ip que se envia como respuesta del dns 
								ubicacion = lenURL + 172
								ip_Respuesta[num] = payload(ubicacion,ubicacion + 8)	
								
								num = num + 1
							
							if (ip_Respuesta[0] == ip_Respuesta[1]):
								enviar.enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
							else:
								num = 0
								while(num < 2)
									if self.ListaDNS[num]['srcip'] != "8.8.8.8"
										enviar.enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
									num = num + 0	
							

							
							
							
				else:
					#Cualquier otro tipo de paquete que se reciba no se analiza en este proyecto por lo que se envia el paquete sin niguna restriccion.
					enviar.enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
				print "Ver si se envia al puerto de la honeynet" 
			else:
				enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
				
			
		
		#Se determinara si el paquete recibido, es o no del tipo RARP
		elif tipoo == 32821:
			#paquete RARP
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
						enviar.enviar_paquete(paqueteARP,self.network,self.IpPuerto[dstip])
					num = num + 1
			#Si solo llega una respuesta actualizamos el diccionario IpMac y enviamos el paquete original a que se realice el ARP			
			else:
				IpMac[srcip] = srcmac
				arp.ejecutarARP(paqueteARP,self.network, self.IpPuerto, self.IpMac, self.paqueteARP)
				

	def payload(num1,num2):	
		of_payload_code = pkt['raw']
		#A continucaion se codifica en hexadecimal dicho payload
		of_payload = of_payload_code.encode("hex")
		#A continuacion se  extrae alguas bandetas de TCP, aquellas que nos indican si es syn, syn-ack y ack  
		return of_payload[num1:num2]


def main():
	#print "Ejecutando main.."
	return ControladorHoneynet()
