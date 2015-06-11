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


def smurf(pkt, ipBroadcast):

	try:
		tipoPkt = pkt['ethtype']
		protocolo = pkt['protocol']
		dstip = pkt['dstip']
	except:
		print "Error"
	
	if tipoPkt == 2048 and protocolo == 1:		
		if (dstip == ipBroadcast):			
			respuesta = "HONEYNET"

		else:
			respuesta = "LAN"
	else:
		respuesta = "LAN"
	return respuesta
	
#Clase terminada  completamente... Revisar!!!!