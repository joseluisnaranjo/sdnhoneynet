###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################
#Nuevo comentario
import syn_flood
import protocolo_ip
import enviar
import protocolo_arp
import thc_ssl_dos
import dns_spoofing
from pyretic.lib.corelib import *
from pyretic.lib.query import *
from ConfigParser import ConfigParser


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
    IpNumS = {}
    IpNumC = {}
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

            try:
                tipoPkt = pkt['ethtype']
                red = self.network
                dstip = pkt['dstip']
                protocolo = pkt['protocol']
                dstport = pkt['dstport']
                srcport = pkt['srcport']

            except:
		        print "%%%%%%%%%%%%%%%%%%%%"

            if tipoPkt == 2054:
                if dstip != IPAddr('192.168.0.1'):
                    protocolo_arp.manejadorArp(pkt, red)

            elif tipoPkt == 2048:
                try:
                    if protocolo == 6:
                        enviar.enviar_paquete(pkt,red)
                        if dstport == 443 or srcport == 443:
                            thc_ssl_dos.thc_ssl_dos(red, pkt, self.ListaAtacantesT, self.ListaClientesT, self.ListaSolicitudesT, self.IpNumC, self.IpNumS)
                        else:
                            enviar.enviar_paquete(pkt,red)
                    '''if (dstmac != EthAddr('ff:ff:ff:ff:ff:ff') or (dstip != IPAddr('239.255.255.250'))):
                        proceso = protocolo_ip.manejadorIp(pkt,  self.IpMac, self.Paquete, self.lstSrcMac, self.lstMacAtacante)
                        if proceso == "TCP":
                            proceso = syn_flood.tcp_syn_flood(pkt, self.ListaAtacantes, self.ListaClientes, self.ListaSolicitudes, self.IpNum)
                            if proceso== "THC":
                                print("llamar al archivo ssl")
                                thc_ssl_dos.thc_ssl_dos(red,pkt,self.ListaAtacantesT, self.ListaClientesT, self.ListaSolicitudesT, self.IpNum)
                            elif proceso == "HONEYNEY":
                                print("enviar al honeynet")
                                enviar.enviar_Honeynet(pkt, red)
                        elif proceso == "UDP":
                            print("llamar al dns_spoofing")
                            dns_spoofing.dns_spoofing(pkt, red)
                        elif proceso == "HONEYNET":
                            print("enviar al honeynet")
                            enviar.enviar_Honeynet(pkt, red)'''
                except:
                    enviar.enviar_paquete(pkt,red)

            else:
                print "Paquete desconocido"

def main():
	return ControladorHoneynet()

