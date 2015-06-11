###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################


import os
from pyretic.lib.corelib import *
from pyretic.lib.query import *
from ConfigParser import ConfigParser



def ip_spoofing(pkt, dicIpMac, dicMacPuerto, lstMacAtacante, puertoHoneynet):
    tipoPkt = ""
    srcip = ""

    try:        
        tipoPkt = pkt['ethtype']
        srcip = pkt['srcip']
        dstmac = pkt ['dstmac']
		srcmac = pkt['srcmac']
    except:
        print "Error"
		
    respuesta = ""


    if srcmac in lstMacAtacante:
        respuesta = "HONEYNET"
    else:
        if tipoPkt == 2054:
            dicIpMac[srcip]= srcmac
            return  "TODO"
        elif tipoPkt == 2048:
            inport = pkt['inport']
            if inport == puertoHoneynet:
                if dicMacPuerto.has_key(dstmac):
                    return "ATACANTE"
                else:
                    return "FIN"
            else:
                if dicIpMac.has_key(srcip):
                    if srcmac == dicIpMac[srcip]:
                        respuesta = "LAN"
                    else :
                        lstMacAtacante.append(srcmac)
                        dicMacPuerto[srcmac] = inport
                        respuesta = "HONEYNET"
                else:
                    respuesta = "LAN"


    return respuesta


def payload(pkt,num1,num2):
    of_payload_code = pkt['raw']
    of_payload = of_payload_code.encode("hex")
    bandera = of_payload[num1:num2]
    return bandera




#Clase terminada  completamente... Revisar!!!!