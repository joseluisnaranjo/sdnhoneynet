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


def ejecutarARP(pkt, network, IpPuerto, IpMac):
    	switch = pkt['switch']
    	inport = pkt['inport']
    	srcip  = pkt['srcip']        
    	dstip  = pkt['dstip']        
    	opcode = pkt['protocol']
	srcmac = pkt['srcmac']

	#Se determina si la ip de origen  esta en el diccionario IPPuerto, caso contrario se la agrega.
	if not srcip in IpPuerto:
		IpPuerto[srcip] = inport
		if not srcip in IpMac:
			IpMac[srcip] = srcmac
			ejecutarEnvio(pkt, network, IpPuerto)

		else:
			if IpMac[srcip] != srcmac:
				enviar.enviar_RARP(pkt,network,srcmac)

	else:
	ejecutarEnvio(pkt, network, IpPuerto)



def ejecutarEnvio(pkt, network, IpPuerto):
	#Si el paquete ARP recibido, es una solicitud se procede a  reenviarlo por todos los puerto, escepto por elq ue llego.
	if opcode == 1:
		for port in network.topology.egress_locations() - {Location(switch,inport)}:
			puerto = port.port_no					
			if inport != puerto:
				enviar.enviar_paquete(pkt,network,puerto)
	# Si el paquete recibido es una respuesta ARP se la enviara unicamente por el puerto en el quese encuentre la Ip destino.
	elif opcode == 2:			
		try: 
			enviar.enviar_paquete(pkt,network,IpPuerto[dstip])
					
		except:
			print "Error en el envio de la respuesta ARP"
		    	print pkt


#Clase terminada  completamente... Funcionando!!!!
