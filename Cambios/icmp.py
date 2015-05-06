###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################
#Nuevo comentario
import collections
import arp
import syn_flood
import enviar
import dns_spoofing
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from ConfigParser import ConfigParser
import os
import binascii
import socket
import syn_flood_andres

def smurf(pkt, network, IpPuerto,IpMac, Listas, puertoHoneynet):
	srcip = pkt['srcip']
	srcmac = pkt['srcmac']
	switch = pkt['switch']
	inport = pkt['inport']
	dstport = pkt['dstport']

	print "Paquete ICMP"

        if (dstip == ipBroadcast):
            print ("Enviar a la honeynet")
            respuesta = "HONEYNET"

        else:
            if ((icmp_replay == "00" ) and (srcip == ipGateway)):
                lstSrcMac.append(srcmac)
                time.sleep(5)
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
                else:
                    IpMac[srcip] = srcmac
                    lstSrcMac.clear()
                    paquete = Packet()
                    print ("Enviar al proceso 1...")
                    respuesta = "TCP"

            else:
                respuesta = verificarIpSpoofing(IpMac, pkt, ipGateway, paquete, lstMacAtacante)
