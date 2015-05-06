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
import demo_syn_flood
import demo_protocolo_ip
import enviar
import demo_protocolo_arp
import demo_thc_ssl_dos
import demo_dns_spoofing
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from ConfigParser import ConfigParser
import os
import binascii
import socket


class ControladorHoneynet(DynamicPolicy):
    config = ConfigParser()
    config.read("honeynet.cfg")
    IpPuerto = {}
    IpMac = {}
    Paquete = Packet()
    lstSrcMac = []
    lstMacAtacante = []
    ListaSolicitudes = []
    ListaAtacantes = []
    ListaClientes = []
    ListaSolicitudesT = []
    ListaAtacantesT = []
    ListaClientesT = []
    ListaRARP = []
    ListaDNS = []
    paqueteARP = Packet()
    identificador = ""
    lenURL = 0
    num = 0
    puertoHoneynet = config.get("PUERTOS","puertoHoneynet")
    print "Ejecutando la aplicacion para el controlador de la Honeynet... "

    def __init__(self):
		print "Se iniciara el constructor de la clase.."
		self.query = packets()
		self.remotes_ip = {}
		self.IpPuerto = {}
		self.IpMac = {}
		self.IpMacAtacante = {}

		self.query.register_callback(self.paquete)
		self.network = None
		super(ControladorHoneynet,self).__init__(self.query)
		print "Ha terminado la ejecucion del constructor.."
    def set_network(self, network):
		self.network = network

    def paquete(self,pkt):
            #tipoPkt = ""
            #red = self.network

            try:
                tipoPkt = pkt['ethtype']
                inport = pkt['inport']
                srcip  = pkt['srcip']
                dstip = pkt['dstip']
                red = self.network
                dstmac = pkt['dstmac']

            except:
		        print "%%%%%%%%%%%%%%%%%%%%"

            send (pkt, self.network)




def main():
	#print "Ejecutando main.."
	return ControladorHoneynet()

ip=IPAddr('192.168.0.255')
def policy():
    return (match(srcip=ip)>>drop)


def send(rp,network):
    for port in network.topology.egress_locations():
        puerto = port.port_no
        rp = rp.modify(outport=puerto)
        network.inject_packet(rp)
        print "Paquete enviado exitosamente!!..."






def manejadorProtocolos(rp,network, IpPuerto):
    dstip = rp['dstip']
    rp = rp.modify(outport=int(IpPuerto[dstip]))
    network.inject_packet(rp)
    print "Paquete enviado exitosamente!!..."

def ejecucion(pkt, network , puertoBloqueado, num):
            #print "se a recibido el paquete numero = " + str(num)
            try:
                switch = pkt['switch']
            	inport = pkt['inport']
            	tipoo = pkt['ethtype']
            	srcmac = pkt['srcmac']
            	dstmac = pkt['dstmac']
            	opcode = pkt['protocol']
            	dstip = pkt['dstip']
                srcip  = pkt['srcip']
            except:
                print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"

            if  tipoo == 2054:
				print "paquete arp"
				for port in network.topology.egress_locations() - {Location(switch,inport)} - {Location(switch, puertoBloqueado)}:
					puerto = port.port_no
					print "puerto entrada = " + str(inport)
					print "puerto switch = " + str(puerto)
					enviar.enviar_paquete(pkt,network,puerto)
					print "****************************************"
				ControladorHoneynet.num=ControladorHoneynet.num+1

            elif tipoo == 2048:
				print "paquete IP "
				for port in network.topology.egress_locations() - {Location(switch,inport)} - {Location(switch, puertoBloqueado)}:
					puerto = port.port_no
					print "puerto entrada = " + str(inport)
					print "puerto switch = " + str(puerto)
					enviar.enviar_paquete(pkt,network,puerto)
					print "//////////////////////////////////////"
				ControladorHoneynet.num=ControladorHoneynet.num+1
            else:
				print "Paquetes desconocidos "
				for port in network.topology.egress_locations() - {Location(switch,inport)} - {Location(switch, puertoBloqueado)}:
					puerto = port.port_no
					print "puerto entrada = " + str(inport)
					print "puerto switch = " + str(puerto)
					enviar.enviar_paquete(pkt,network,puerto)
					print "???????????????????????????????????????????????"

				num=num+1

