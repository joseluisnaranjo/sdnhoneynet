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
	dstip = pkt['srcip']
	
	if (dstip == ipBroadcast):
		print ("Paquete peligroso...")
		respuesta = "HONEYNET"

	else:
		print ("Paquete legitimo...")
		respuesta = "LAN"
	return respuesta
	
#Clase terminada  completamente... Revisar!!!!