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



def ip_spoofing(pkt, IpMac, paquete, lstSrcMac, lstMacAtacante, ipGateway):
   
    protocolo = pkt['protocol']
    srcip  = pkt['srcip']
    dstip = pkt['dstip']
    srcmac = pkt['srcmac']

    of_payload_code = pkt['raw']
    of_payload = of_payload_code.encode("hex")
    icmp_replay = str(of_payload[68:70])

    if protocolo == 1:
		if ((icmp_replay == "00" ) and (dstip == ipGateway)):
			lstSrcMac.append(srcmac)
			time.sleep(1)
			if (len(lstSrcMac)>1):
				for i in lstSrcMac:
					if i == paquete['srcmac']:
						lstMacAtacante.append(paquete['srcmac'])
						lstSrcMac.clear()
						paquete = Packet()
						print ("Paquete peligroso")
						respuesta = "HONEYNET"

					else :
						respuesta = ""
			else:
				IpMac[srcip] = srcmac
				lstSrcMac.clear()
				paquete = Packet()
				print ("Pkt legitimo")
				respuesta = "LAN"

		else:
			respuesta = verificarIpSpoofing(IpMac, pkt, ipGateway, paquete, lstMacAtacante)


    else:
        respuesta = verificarIpSpoofing(IpMac, pkt, ipGateway, paquete, lstMacAtacante)

    return respuesta


def verificarIpSpoofing(IpMac, pkt, ipGateway, paquete, lstMacAtacante):
    srcmac = pkt['srcmac']
    srcip = pkt['srcip']

    if (srcmac in lstMacAtacante):
        print ("paquete peligroso")
        respuesta = "HONEYNET"

    else:
        if (IpMac.has_key(srcip)):
            if (IpMac[srcip]== srcmac):
                print ("Paquete conocido... ")
                respuesta = "LAN"

            else:
                if (paquete == Packet()):
                    print ("Enviar un ping a: " + str(pkt['srcip']))
                    paquete = pkt
                    comando = "sudo hping3 -1 -c 1" + str(srcip) + " -a " + str(ipGateway)
                    print comando
                    os.system(comando)
                    respuesta = ""
                else:
                    respuesta = ""
        else:
            IpMac[srcip] = srcmac
            print("Paquete nuevo...")
            respuesta = "LAN"
			
	return respuesta

#Clase terminada  completamente... Revisar!!!!