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





















                





















###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

from pyretic.lib.corelib import *
from ConfigParser import ConfigParser
import enviar
def thc_ssl_dos(red, pkt, ListaAtacantes, ListaClientes, ListaSolicitudes, IpNumC, IpNumS):
    config = ConfigParser()
    config.read("honeynet.cfg")
    ipServidor = config.get("SYNFLOOD", "ipServidor")
    num_max_conexiones = config.getint("SYNFLOOD", "num")
    tamano_max_listasolicitudes = config.getint("SYNFLOOD", "tamano")
    srcip  = pkt['srcip']
    dstip  = pkt['dstip']

    ssl_flags1= payload(pkt, 118, 120)
    ssl_flags2 = payload(pkt, 142, 144)
    ssl_dato1 = payload(pkt, 108, 110)
    ssl_dato2 = payload(pkt, 132, 134)



    print" SSL desde:" +  str (srcip)
    if (str(ssl_flags1) == "01") or (str(ssl_flags2) == "01"):
        if srcip == IPAddr(ipServidor):
            print"paquete ssl del servidor"
            enviar.enviar_paquete(pkt,red)
        else:
                if srcip in ListaAtacantes:
                    print "Enviar ala Honeynet...Esta en lista de atacantes"
                    enviar.enviar_Honeynet(pkt, red)

                else:
                    if srcip in ListaSolicitudes:
                        if IpNumS.has_key(srcip):
                                if IpNumS[srcip] < num_max_conexiones:
                                    IpNumS[srcip] = IpNumS[srcip] + 1
                                    print "Enviar a la LAN...Menos de 10 solicitudes"
                                    enviar.enviar_paquete(pkt, red)
                                else:
                                    ListaSolicitudes.remove(srcip)
                                    ListaAtacantes.append(srcip)
                                    del IpNumS[srcip]
                                    print "Enviar ala Honeynet...Mas de 10 solicitudes"
                                    enviar.enviar_Honeynet(pkt, red)
                        else:
                            IpNumS[srcip] = 1
                            print "Enviar a la LAN...Primera solicitud"
                            enviar.enviar_paquete(pkt, red)

                    else:
                        if srcip in ListaClientes:
                            if IpNumC.has_key(srcip):
                                if IpNumC[srcip] < num_max_conexiones:
                                    IpNumC[srcip] = IpNumC[srcip] + 1
                                    print "Enviar a la LAN...Menos de 10 solicitudes"
                                    enviar.enviar_paquete(pkt, red)
                                else:
                                    ListaClientes.remove(srcip)
                                    ListaAtacantes.append(srcip)
                                    del IpNumC[srcip]
                                    print "Enviar ala Honeynet...Mas de 10 solicitudes"
                                    enviar.enviar_Honeynet(pkt, red)
                            else:
                                IpNumC[srcip] = 1
                                print "Enviar a la LAN...Primera solicitud"
                                enviar.enviar_paquete(pkt, red)
                        else:
                            if len(ListaSolicitudes) < tamano_max_listasolicitudes:
                                ListaSolicitudes.append(srcip)
                                print "Enviar a la LAN...Lista de solicitudes menor al maximo"
                                enviar.enviar_paquete(pkt, red)
                            else:
                                ListaAtacantes.append(ListaSolicitudes[0])
                                del ListaSolicitudes[0]
                                ListaSolicitudes.append(srcip)
                                print "Enviar a la LAN...Lista de solicitudes mayor al maximo"
                                enviar.enviar_paquete(pkt, red)
    else:
                if (str(ssl_dato1) == "17") or (str(ssl_dato2) == "17"):
                    if dstip in ListaSolicitudes:
                        ListaSolicitudes.remove(dstip)
                        ListaClientes.append(dstip)
                        IpNumS[dstip] = IpNumS[dstip] - 1
                        print "Enviar a la LAN...sacando de la lista de solicitudes"
                        enviar.enviar_paquete(pkt, red)

                    else:
                        if dstip in ListaAtacantes:
                             ListaAtacantes.remove(dstip)
                             ListaClientes.append(dstip)
                             print "Enviar a la LAN...sacando de lsiat de atacantes"
                             enviar.enviar_paquete(pkt, red)

                        else:
                            if dstip in ListaClientes:
                                print "Enviar a la LAN... de la lsita de clientes"
                                enviar.enviar_paquete(pkt, red)
                else:
                    if srcip in ListaAtacantes:
                        print "Enviar a la Honeynet... datos desconocidos...de la lista de atacantes"
                        enviar.enviar_Honeynet(pkt,red)
                    else:
                        print "Enviar a la LAN...... datos desconocidos...No esta en la lista de atacantes"
                        enviar.enviar_paquete(pkt, red)


def payload(pkt,num1,num2):
    of_payload_code = pkt['raw']
    of_payload = of_payload_code.encode("hex")
    print of_payload
    return of_payload[num1:num2]
















