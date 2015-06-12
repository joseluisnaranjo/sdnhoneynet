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


def arp_spoofing(pkt,dicSolicitudesARP, dicMacIpSol,  dicMacPuerto, lstAtacantesARP):
	try:
		tipoPkt = pkt['ethtype']

	except:
		print ""
	respuesta = ""
	if tipoPkt == 2054:
		protocolo = pkt['protocol']
		dstip  = pkt['dstip']
		srcip = pkt['srcip']
		srcmac = pkt['srcmac']
		dstmac = pkt['dstmac']
		if dstmac in lstAtacantesARP:
			return "ATACANTE"
		elif srcmac in lstAtacantesARP:
			return "HONEYNET"

		elif tipoPkt == 2054:
			inport = pkt['inport']
			if protocolo == 1:
				dicMacIpSol[srcmac]= srcip
				if dicSolicitudesARP.has_key(dstip):

					dicSolicitudesARP[dstip] = dicSolicitudesARP[dstip] + 1
					respuesta = "LAN"

				else:
					dicSolicitudesARP[dstip]= 1
					respuesta = "LAN"

			elif protocolo == 2:

					if dicMacIpSol.has_key(srcmac):
						if dicMacIpSol[srcmac] == srcip:
							respuesta = "LAN"
							if srcmac in lstAtacantesARP:
								lstAtacantesARP.remove(srcmac)

						else:
							del dicMacIpSol[srcmac]
							respuesta = "HONEYNET"


					else:
						if dicSolicitudesARP.has_key(srcip):
							if  dicSolicitudesARP[srcip] >= 0:
								dicSolicitudesARP[srcip] = dicSolicitudesARP[srcip] - 1
								respuesta = "LAN"
							else:
								lstAtacantesARP.append(srcmac)
								dicMacPuerto[srcmac]= inport
								respuesta = "HONEYNET"
						else:
							lstAtacantesARP.append(srcmac)
							dicMacPuerto[srcmac]= inport
							respuesta = "HONEYNET"
			else:
				respuesta = "LAN"
		else:
			respuesta = "LAN"
			print pkt
	else:
		respuesta = "LAN"

	return respuesta



#Clase terminada  completamente... Revisar!!!!