
###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

import collections
import enviar
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
import controlador
from ConfigParser import ConfigParser


def ejecutarARP(pkt, network, IpPuerto,puertoHoneynet, IpMac, paqueteARP, IpMacAtacante):
	config = ConfigParser()
	config.read("honeynet.cfg") #Se ha creado una instancia de la clase ConfigParser que nos permite  leer un archivo de configuracion    
	puertoHoneynet = config.get("PUERTOS","puertoHoneynet")
	inport = pkt['inport']
	srcip  = pkt['srcip']        
	dstip  = pkt['dstip']        
	srcmac = pkt['srcmac']

	
	#Se determina si la ip de origen esta en el diccionario IPPuerto
	#El primer lazo if ayuda unicamente a llenar el diccionario IpPuerto
	if srcip in IpPuerto:
		#Si es que ya existe se envia directamente"
		try:
			tipoARP(pkt, network, IpPuerto[dstip])
		except:
			enviar.enviar_ARP(pkt, network)

	#Si no se encuentra en el diccionario se lo ingresa 
	else:
		IpPuerto[srcip] = inport
		#Se comprueba si la direccion ip de origen ya se encuentra en el diccionario
		if srcip in IpMac:
			#Si ya existe esa ip se comrueba que la mac origen corresponde a la almacenada en el diccionario
			if IpMac[srcip] == srcmac:
				#Si ya esta registrada se envia el paquete ya que es un cliente fiable
				tipoARP(pkt, network, IpPuerto[dstip])
			#Si ya no esta registrado podemos dudar si se trata de una atacante 
			else:
				#Se guarda el paquete ARP hasta comprobar si el cliente es fiable o no
				paqueteARP = pkt
				#Ya que se esta dudando, para comprobar se envia un paquete RARP
				enviar.enviar_RARP(pkt,network)

		#A continuacion se comprueba si esta en el diccionario de atacantes 
		elif srcip in IpMacAtacante:
			#Una ves que sabemos que esta en el diccionario de atacantes enviamos a la honeynet
			tipoARP(pkt, network, puertoHoneynet)
		
		#Si no se encuentra en el diccionario IpMac quiere decir que es un cliente nuevo
		else:
			#Como se trata de un cliente nuevo se incluye en el diccionario y se envia el paquete
			IpMac[srcip] = srcmac
			try:
				tipoARP(pkt, network, IpPuerto[dstip])
			except:
				tipoARP(pkt, network, 0)


def tipoARP(pkt, network, puerto):
	config = ConfigParser()
	config.read("honeynet.cfg") #Se ha creado una instancia de la clase ConfigParser que nos permite  leer un archivo de configuracion    
	puertoHoneynet = config.get("PUERTOS","puertoHoneynet")
	switch = pkt['switch']
	opcode = pkt['protocol']
	inport = pkt['inport']
	dstip  = pkt['dstip']
	#Si el paquete ARP recibido, es una solicitud se procede a  reenviarlo por todos los puerto, escepto por el que llego.
	if opcode == 1:

		for port in network.topology.egress_locations() - {Location(switch,inport)}:
			puerto = port.port_no					
			if ((inport != puerto) and (puertoHoneynet != puerto)):
				enviar.enviar_paquete(pkt,network,puerto)
	# Si el paquete recibido es una respuesta ARP se la enviara unicamente por el puerto en el quese encuentre la Ip destino.
	elif opcode == 2:			
		try: 
			enviar.enviar_paquete(pkt,network,puerto)
					
		except:
			print "Error en el envio de la respuesta ARP"
		    	print pkt


#Clase terminada  completamente... Funcionando!!!!
