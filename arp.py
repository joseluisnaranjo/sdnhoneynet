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


def arp_spoofing(pkt,dicSolicitudes, dicMacIp,  dicMacPuerto, lstAtacantes):
	srcmac = ""
	dstmac = ""
	try:
		tipoPkt = pkt['ethtype']
		srcmac = pkt['srcmac']
		dstmac = pkt['dstmac']

	except:
		print ""
	respuesta = ""

	if tipoPkt == 2054:
		inport = pkt['inport']
		protocolo = pkt['protocol']
		dstip  = pkt['dstip']
		srcip = pkt['srcip']
		if protocolo == 1:
			dicMacIp[srcmac]= srcip
			if dicSolicitudes.has_key(dstip):
				dicSolicitudes[dstip] = dicSolicitudes[dstip] + 1
				respuesta = "LAN"
			else:
				dicSolicitudes[dstip]= 1
				respuesta = "LAN"

		elif protocolo == 2:
				if dicMacIp.has_key(srcmac):
					if dicMacIp[srcmac] == srcip:
						respuesta = "LAN"
						if srcmac in lstAtacantes:
							lstAtacantes.remove(srcmac)
					else:
						del dicMacIp[srcmac]
						respuesta = "HONEYNET"
				else:
					if dicSolicitudes.has_key(srcip):
						if  dicSolicitudes[srcip] >= 0:
							dicSolicitudes[srcip] = dicSolicitudes[srcip] - 1
							respuesta = "LAN"
						else:
							if srcmac not in lstAtacantes:
								lstAtacantes.append(srcmac)
							dicMacPuerto[srcmac]= inport
							respuesta = "HONEYNET"
					else:
						if srcmac not in lstAtacantes:
							lstAtacantes.append(srcmac)
						dicMacPuerto[srcmac]= inport
						respuesta = "HONEYNET"
		else:
			respuesta = "LAN"
	else:
		if dstmac in lstAtacantes:
			return "ATACANTE"
		elif srcmac in lstAtacantes:
			return "HONEYNET"
		else:
			respuesta = "LAN"

	return respuesta



#Clase terminada  completamente... Revisar!!!!