
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


def arp_spoofing(pkt, lstARP):
    protocolo = pkt['protocol']
    dstip  = pkt['dstip']
    srcip = pkt['srcip']
    respuesta = ""


    if protocolo == 1:
        if dstip in lstARP:
            respuesta = "FIN"
        else:
            lstARP.append(dstip)
            respuesta = "LAN"
        return respuesta


    elif protocolo == 2:
        if srcip in lstARP:
            lstARP.remove(srcip)
            respuesta = "LAN"

        else:
            respuesta = "HONEYNET"

        return respuesta
    else:
        return "LAN"
			

	
#Clase terminada  completamente... Revisar!!!!
