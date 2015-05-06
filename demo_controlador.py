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
import thread


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



            if tipoPkt == 2054:
                if dstip != IPAddr('192.168.0.1'):
                    demo_protocolo_arp.manejadorArp(pkt, red)


            elif tipoPkt == 2048:
                if dstmac != EthAddr('ff:ff:ff:ff:ff:ff'):
                    proceso = demo_protocolo_ip.manejadorIp(pkt,  self.IpMac, self.Paquete, self.lstSrcMac, self.lstMacAtacante)
                    if proceso == "TCP":
                        proceso = demo_syn_flood.tcp_syn_flood(pkt, self.ListaAtacantes, self.ListaClientes, self.ListaSolicitudes )
                        if proceso== "THC":
                            print("llamar al archivo ssl")
                            demo_thc_ssl_dos.thc_ssl_dos(red,pkt,self.ListaAtacantesT, self.ListaClientesT, self.ListaSolicitudesT)
                        elif proceso == "HONEYNEY":
                            print("enviar al honeynet")
                            enviar.enviar_Honeynet(pkt, red)
                    elif proceso == "UDP":
                        print("llamar al dns_spoofing")
                        demo_dns_spoofing.dns_spoofing(pkt, red)
                    elif proceso == "HONEYNET":
                        print("enviar al honeynet")
                        enviar.enviar_Honeynet(pkt, red)



            else:
                #manejadorProtocolos(pkt, red)
                #enviar.enviar_paquete(pkt, red)
                print "Paquete desconocido"

                #print "se ha recibido el paquete numero = " + str(self.num)




def main():
	#print "Ejecutando main.."
	return ControladorHoneynet()

'''def send(rp,network, IpPuerto):
    dstip = rp['dstip']
    rp = rp.modify(outport=int(IpPuerto[dstip]))
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

				num=num+1'''

