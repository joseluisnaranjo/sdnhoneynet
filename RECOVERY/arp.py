
###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

import collections
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *



def arp_spoofing(pkt, red, lstARP):
	protocolo = pkt['protocol']
	dstip  = pkt['dstip']
	#Si el paquete ARP recibido, es una solicitud 
	if protocolo == 1:
		lstARP.add(dstip)
		return LAN

	# Si el paquete recibido es una respuesta ARP 
	elif protocolo == 2:
		if srcip in lstARP:
			return LAN
		else:
			return HONEYNET
		
#Clase terminada  completamente... Revisar!!!!
