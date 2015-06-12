###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################
#Nuevo comentario
import arp
import ip
import tcp
import udp
import icmp
import https
import enviar
from pyretic.lib.corelib import *
from pyretic.lib.query import *
from ConfigParser import ConfigParser


class ControladorHoneynet(DynamicPolicy):
    config = ConfigParser()
    config.read("honeynet.cfg")
	
    dicSolicitudesARP = {} #arp
    dicMacIp = {} #arp
    dicMacPuertoARP = {} # ip
    ListaAtacantesARP = [] # arp

    IpMac = {} #ip
    MacPuerto = {} # ip
    lstMacAtacante = [] #ip

    dicSolicitudesT = {}  # tcp
    lstAtacantesT = []  # tcp
    dicClientesT = {}  # tcp

    dicSolicitudesS = {}  # ssl
    lstAtacantesS = []  # ssl
    dicClientesS = {}  # ssl

    ListaAtacantesDNS = [] # udp


    puertoHoneynet = config.getint("PUERTOS", "puertoHoneynet")
    ipServidor = config.get("IPS","ipServidor") # tcp
    ipBroadcast = config.get("IPS","ipBroadcast") # tcp
    macGateway = config.get("MACS","macGateway") #udp
    num_max_conexiones = config.getint("CONEXIONES","numeroConexiones") # tcp
    num_max_solicitudes = config.getint("SOLICITUDES", "numeroSolicitudes") #arp
    proceso = config.getint("PROCESOS","proceso") # General


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

    def paquete(self,pkt ):

        try:
            red = self.network
            dstmac = pkt ['dstmac']
        except:
            print pkt

        respuesta = ""
			
        if self.proceso == 0:
			respuesta = arp.arp_spoofing(pkt, self.dicSolicitudesARP, self.dicMacIp,self.dicMacPuertoARP, self.ListaAtacantesARP)
			if respuesta == "LAN":			
				respuesta = ip.ip_spoofing(pkt,  self.IpMac, self.MacPuerto, self.lstMacAtacante, self.puertoHoneynet)
				if respuesta == "LAN":
					respuesta = tcp.tcp_syn_flood(pkt, self.lstAtacantesT, self.dicSolicitudesT, self.dicClientesT, IP(self.ipServidor), self.num_max_conexiones)
					if respuesta == "LAN":
						respuesta = udp.dns_spoofing(pkt, self.ListaAtacantesDNS, MAC(self.macGateway))				
						if respuesta == "LAN":
							respuesta = icmp.smurf(pkt, IP(self.ipBroadcast))
							if respuesta == "LAN":		
							    respuesta = https.thc_ssl_dos(pkt, self.lstAtacantesS, self.dicSolicitudesS, self.dicClientesS, IP(self.ipServidor), self.num_max_conexiones)
             


        elif self.proceso == 1:
            respuesta = arp.arp_spoofing(pkt, self.dicSolicitudesARP, self.dicMacIp,self.dicMacPuertoARP, self.ListaAtacantesARP)


        elif self.proceso == 2:
			respuesta = ip.ip_spoofing(pkt,  self.IpMac, self.MacPuerto, self.lstMacAtacante, self.puertoHoneynet)


        elif self.proceso == 3:
            respuesta = tcp.tcp_syn_flood(pkt, self.lstAtacantesT, self.dicSolicitudesT, self.dicClientesT, IP(self.ipServidor), self.num_max_conexiones)
               

        elif self.proceso == 4:
            respuesta = udp.dns_spoofing(pkt, self.ListaAtacantesDNS, MAC(self.macGateway))


        elif self.proceso == 5:
			respuesta = icmp.smurf(pkt, IP(self.ipBroadcast))
			
			
        elif self.proceso == 6:
            respuesta = https.thc_ssl_dos(pkt, self.lstAtacantesS, self.dicSolicitudesS, self.dicClientesS, IP(self.ipServidor), self.num_max_conexiones)
                      


        if respuesta == "LAN":
            enviar.enviar_Lan(pkt, red, self.puertoHoneynet)
        elif respuesta == "HONEYNET":
            enviar.enviar_Honeynet(pkt, red, self.puertoHoneynet)
        elif respuesta == "TODO":
            enviar.enviar_Todo(pkt, red)
        elif respuesta == "ATACANTE":
            enviar.enviar_Honeynet(pkt, red, self.MacPuerto[dstmac])


def main():
	return ControladorHoneynet()

