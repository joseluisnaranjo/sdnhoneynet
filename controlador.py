###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################
#Comentario para comprobar  cambios  usando sudo git fetch..
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
				#A continuacion de extrae el payload codificado (paquete original) del pkt OpenFlow
				of_payload_code = pkt['raw']
				#A continucaion se codifica en hexadecimal dicho payload
				of_payload = of_payload_code.encode("hex")
				#A continuacion se  extrae alguas bandetas de TCP, aquellas que nos indican
				tcp_flags = of_payload[94:96]
				print b
				#Se obtiene  de un archivo de configuracion la ip del servidor 
				ipServidor = self.config.get("SYNFLOOD","ipServidor")
				if tcp_flags == "02":
					tamano_actual_listasolicitudes = len(self.ListaSolicitudes)
					#Se obtiene  de un archivo de configuracion el tamaño maximo que puede tener la lista de Solicitudes de conexion TCP que ha recibido el servidor 
					tamano_max_listasolicitudes = self.config.get("SYNFLOOD","tamano")
					#A continuacion se verifica que el tamano de la lsiat sea menor al maximo especificado en el archivo de configuracion
					if tamano_actual_listasolicitudes < tamano_max_listasolicitudes:
						#A continuacion se verifica que la direccion IP origen del segmento TCP recibido no sea la del servidor
						if srcip != ipServidor:
							#A continuacion se verifica que la direccion IP origen del segmento TCP recibido no se encuentre en la lista de solicitudes
							if not srcip in self.ListaSolicitudes:
								#A continuacion se verifica que la direccion IP origen del segmento TCP recibido no se encuentre en la lista de atacantes
								if not srcip in self.ListaAtacantes:
									#A continuacion se verifica que la direccion IP origen del segmento TCP recibido no se encuentre en la lista de Clientes lejitimos
									if not srcip in self.ListaClientes:
										#Debido a que noe staba en al lista de cleintes lejitimos, se procede a añadirla
										self.ListaSolicitudes.append(srcip)
										#Se verifica que efectiamnete  se aya añadidoa alsita 
										if self.ListaSolicitudes[-1] == srcip:
											enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
										else:
											print "Error al añadir  a la lista..."
									else:	
										print "66666"
										enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
								else:
									print "77777"
									enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
							else:
								#Si la direccion IP origen del segmento TCP recibido SI se encuentre en la lista de solicitudes, entonces se procede a borrarla de dicha lista y,
								self.ListaSolicitudes.remove(srcip)
								# Se la agrega a la lista de Atacantes, puesto que se presume  esta intentando hacer un segundo intento de conexion al servidor al mismo timpo..
								self.ListaAtacantes.append(srcip)
								#Sin embargo se deja pasar un solo paquete paga obtener estadisticas...
								Print "Revisar siguiente linea ... no se debe enviar todos los paquetes..."
								enviar_paquete(pkt,self.network,self.IpPuerto[dstip])					
							
						else:
							#En caso que la direccion  Ip de origen es la del servidor, el trafico se debe deja pasar sin ninguna restriccion
							enviar_paquete(pkt,self.network,self.IpPuerto[dstip])
					else:
						#En caso de que el tamano de la lista sea mayor al tamaño maximo especificado, Se añade a la lista de atacantes la primera solicitud que se agrego a la lista de solicitudes pendientes 
						self.ListaAtacantes.append(self.ListaSolicitudes[0])
						# A continuacion se procede a borrar la solicitud que se ha enviado a la lista de atacantes  de la lista de solicitudes para liberar un espacio
						del self.ListaSolicitudes[0]
						# Y finalmente se agrega la nueva solicitud a la lista de solicitudes pendientes 
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
