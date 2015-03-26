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


class ControladorHoneynet(DynamicPolicy):
    IpMac = {}
    lstMacAtacante = []
    lstSrcMac = []
    Paquete = Packet()
    num = 0
    config = ConfigParser()
    config.read("honeynet.cfg")


    print "Ejecutando la aplicacion para el controlador de la Honeynet... "
    def __init__(self):
        print "Se iniciara el constructor de la clase.."

        # Se ha creado una instancia de la clase ConfigParser que nos permite  leer un archivo de configuracion
        IpMac = {}
        IpPaquete = {}
        ListaSolicitudes = []
        ListaAtacantes = []
        ListaClientes = []
        ListaRARP = []
        ListaDNS = []
        paqueteARP = Packet()
        identificador = ""
        lenURL = 0

        self.query = packets()
        self.remotes_ip = {}
        self.query.register_callback(self.paquete)
        self.network = None
        super(ControladorHoneynet, self).__init__(self.query)
        print "Ha terminado la ejecucion del constructor.."

    def set_network(self, network):
        self.network = network

    def paquete(self, pkt):
        try:
            tipoPkt = pkt['ethtype']
            red = self.network
            switch = pkt['switch']

        except:
		    print "%%%%%%%%%%%%%%%%%%%%"

        if tipoPkt == 2054:
            manejadorArp(pkt, red, switch)

        elif tipoPkt == 2048:
            manejadorIp(pkt, red, self.IpMac, self.Paquete, self.lstSrcMac, self.lstMacAtacante)
        else:
            manejadorProtocolos(pkt, red, switch)

        print "se ha recibido el paquete numero = " + str(self.num)


def main():
	#print "Ejecutando main.."
	return ControladorHoneynet()

def manejadorArp(pkt, red, switch):
    print "paquete arp"
    inport = pkt['inport']
    for port in red.topology.egress_locations() - {Location(switch, inport)}:
        puerto = port.port_no
        print "puerto entrada = " + str(inport)
        print "puerto switch = " + str(puerto)
        enviar.enviar_paquete(pkt,red,puerto)
        print "****************************************"
        ControladorHoneynet.num = ControladorHoneynet.num + 1

def manejadorIp(pkt, red,  IpMac, paquete, lstSrcMac, lstMacAtacante):
    print "paquete IP "
    ipGateway = ControladorHoneynet.config.get("IP_SPOOFING", "ipGateway")
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
        #icmpType= pkt['']
        if (dstip == ipBroadcast):
            print ("Enviar a la honeynet")

        else:
            if ((icmp_replay== "00" ) and (srcip==ipGateway)):
                lstSrcMac.append(srcip)
                time.sleep(1)
                if (len(lstSrcMac)>1):
                    for i in lstSrcMac:
                        if i == paquete['srcmac']:
                            lstMacAtacante.append(paquete['srcmac'])
                            lstSrcMac.clear()
                            paquete = Packet()
                            print ("Enviar a la honeynet")

                        else :
                            return
                else :
                    IpMac[srcip]  = srcmac
                    lstSrcMac.clear()
                    paquete = Packet()
                    print ("Enviar a la honeynet")

            else :
                verificarIpSpoofing(IpMac, pkt,red, ipGateway, paquete, lstMacAtacante)

    else :
        verificarIpSpoofing(IpMac, pkt,red, ipGateway, paquete, lstMacAtacante)


def verificarIpSpoofing(IpMac, pkt,red, ipGateway, paquete, lstMacAtacante):
    srcmac = pkt['srcmac']
    srcip  = pkt['srcip']
    if ( lstMacAtacante.count(srcmac)== 0):
        if (IpMac.has_key(srcip)):
            if (IpMac[srcip]== srcmac):
                print ("Paquete conocido... Enviar paquete al proceso 1...")
                enviar.enviar_paquete1(pkt,red,ControladorHoneynet.num)

            else :
                if (paquete == Packet()):
                    print ("Enviar un ping a: " + str(pkt[srcip]))
                    paquete = pkt
                    comando = "hping3 -1 " + str(srcip) + " -a " + str(ipGateway)
                    os.system(comando)
                else :
                    return
        else :
            IpMac[srcip]  = srcmac
            print("Paquete nuevo...Enviar al proceso 1...")
            enviar.enviar_paquete1(pkt,red,ControladorHoneynet.num)
            return
    else :
        print ("Enviar a la honeynet")
        return



def manejadorProtocolos(pkt):
    print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
    print "Paquetes desconocidos "
    inport = pkt['inport']
    print "puerto entrada = " + str(inport)
    print "???????????????????????????????????????????????"

def enviar_paquete(paquete,network,sending_port):
	config = ConfigParser()
	#config.read("honeynet.cfg") #Se ha creado una instancia de la clase ConfigParser que nos permite  leer un archivo de configuracion
	puertoHoneynet = config.get("PUERTOS","puertoHoneynet")
	puertoLAN = config.get("PUERTOS","puertolan")
	inport = paquete['inport']