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


def manejadorIp(pkt, red,  IpMac, paquete, lstSrcMac, lstMacAtacante):
    print "paquete IP "
    ipGateway = config.get("IP_SPOOFING", "ipGateway")
    ipBroadcast = IPAddr('192.168.0.255')
    protocolo = pkt['protocol']
    srcip  = pkt['srcip']
    dstip = pkt['dstip']
    srcmac = pkt['srcmac']


    of_payload_code = pkt['raw']
    of_payload = of_payload_code.encode("hex")
    icmp_replay =str(of_payload[68:70])

    if protocolo == 1:
        print "Paquete ICMP"

        if (dstip == ipBroadcast):
            print ("Enviar a la honeynet")
            respuesta = "HONEYNET"

        else:
            if ((icmp_replay== "00" ) and (srcip==ipGateway)):
                lstSrcMac.append(srcmac)
                time.sleep(1)
                if (len(lstSrcMac)>1):
                    for i in lstSrcMac:
                        if i == paquete['srcmac']:
                            lstMacAtacante.append(paquete['srcmac'])
                            lstSrcMac.clear()
                            paquete = Packet()
                            print ("Enviar a la honeynet")
                            respuesta = "HONEYNET"


                        else :
                            respuesta = ""
                else :
                    IpMac[srcip]  = srcmac
                    lstSrcMac.clear()
                    paquete = Packet()
                    print ("Enviar al proceso 1...")
                    respuesta = "TCP"

            else :
                respuesta =   verificarIpSpoofing(IpMac, pkt, ipGateway, paquete, lstMacAtacante)
    elif protocolo == 17:
        respuesta = "UDP"

    else :
        respuesta =  verificarIpSpoofing(IpMac, pkt, ipGateway, paquete, lstMacAtacante)

    return respuesta


def verificarIpSpoofing(IpMac, pkt, ipGateway, paquete, lstMacAtacante):
    srcmac = pkt['srcmac']
    srcip  = pkt['srcip']

    if (srcmac in lstMacAtacante):
        print ("Enviar a la honeynet")
        return "HONEYNET"

    else :
        if (IpMac.has_key(srcip)):
            if (IpMac[srcip]== srcmac):
                print ("Paquete conocido... Enviar paquete al proceso 1...")
                return "TCP"


            else :
                if (paquete == Packet()):
                    print ("Enviar un ping a: " + str(pkt[srcip]))
                    paquete = pkt
                    comando = "hping3 -1 " + str(srcip) + " -a " + str(ipGateway)
                    os.system(comando)
                    return ""
                else :
                    return ""
        else :
            IpMac[srcip]  = srcmac
            print("Paquete nuevo...Enviar al proceso 1...")
            return "TCP"

