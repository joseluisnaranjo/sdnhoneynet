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

config = ConfigParser()
config.read("honeynet.cfg")
respuesta = ""

def ip_spoofing(pkt, IpMac, paquete, lstSrcMac, lstMacAtacante):
    print "paquete IP "
    ipGateway = config.get("IP_SPOOFING", "ipGateway")
    ipBroadcast = IPAddr('192.168.0.255')
    protocolo = pkt['protocol']
    srcip  = pkt['srcip']
    dstip = pkt['dstip']
    srcmac = pkt['srcmac']

    of_payload_code = pkt['raw']
    of_payload = of_payload_code.encode("hex")
    icmp_replay = str(of_payload[68:70])

    if protocolo == 6:
        respuesta = verificarIpSpoofing(IpMac, pkt, ipGateway, paquete, lstMacAtacante)
        
    elif protocolo == 17:
        respuesta = "UDP"

    else:
        print "protocolo ip desconocido"
        

    return respuesta


def verificarIpSpoofing(IpMac, pkt, ipGateway, paquete, lstMacAtacante):
    srcmac = pkt['srcmac']
    srcip = pkt['srcip']

    if (srcmac in lstMacAtacante):
        print ("Enviar a la honeynet")
        return "HONEYNET"

    else:
        if (IpMac.has_key(srcip)):
            if (IpMac[srcip]== srcmac):
                print ("Paquete conocido... Enviar paquete al proceso 1...")
                return "TCP"

            else:
                if (paquete == Packet()):
                    print ("Enviar un ping a: " + str(pkt['srcip']))
                    paquete = pkt
                    comando = "sudo hping3 -1 -c 1" + str(srcip) + " -a " + str(ipGateway)
                    print comando
                    os.system(comando)
                    return ""
                else:
                    return ""
        else:
            IpMac[srcip] = srcmac
            print("Paquete nuevo...Enviar al proceso 1...")
            return "TCP"

