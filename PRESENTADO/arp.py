
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


def arp_spoofing(pkt,dicSolicitudesARP,dicRespuestasARP, dicMacIpSol, lstAtacantesARP, numerosolicitudes):
	protocolo = pkt['protocol']
	dstip  = pkt['dstip']
	srcip = pkt['srcip']
	srcmac = pkt['srcmac']
	respuesta = ""


	if protocolo == 1:
		dicMacIpSol[srcmac]= srcip
		if dicSolicitudesARP.has_key(dstip):
			dicSolicitudesARP[dstip] = dicSolicitudesARP[dstip] + 1
			respuesta = "LAN"

		else:
			dicSolicitudesARP[dstip]= 1
			respuesta = "LAN"
        
	elif protocolo == 2:
		if srcmac in lstAtacantesARP:
			respuesta = "HONEYNET"
		else:
			if dicMacIpSol.has_key(srcmac):
				if dicMacIpSol[srcmac] == srcip:
					respuesta = "LAN"
				else:
					del dicMacIpSol[srcmac]
			else:
				if dicSolicitudesARP.has_key(srcip):
					if  dicSolicitudesARP[srcip] >= 0:
						dicSolicitudesARP[srcip] = dicSolicitudesARP[srcip] - 1
						respuesta = "LAN"
					else:
						lstAtacantesARP.append(srcmac)
						respuesta = "HONEYNET"
				else:
					lstAtacantesARP.append(srcmac)					
					respuesta = "HONEYNET"        
	else:
		respuesta = "LAN"
		
	return respuesta
			

	
#Clase terminada  completamente... Revisar!!!!
