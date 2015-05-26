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
    IpPuerto = {}
    IpMac = {} #ip
    Paquete = Packet() #ip
    lstSrcMac = [] #ip
    lstMacAtacante = [] #ip

    dicSolicitudesT = {}  # tcp
    lstAtacantesT = []  # tcp
    dicClientesT = {}  # tcp

    dicSolicitudesS = {}  # ssl
    lstAtacantesS = []  # ssl
    dicClientesS = {}  # ssl


    ListaSolicitudesS = []
    ListaAtacantesS = []
    ListaClientesS = []
    ListaAtacantesDNS = [] # udp
    ListaARP = [] # arp
    ListaDNS = []


    paqueteARP = Packet()
    identificador = ""
    lenURL = 0
    num = 0


    puertoHoneynet = config.getint("PUERTOS", "puertoHoneynet")
    ipGateway = config.get("IPS","ipGateway") #ip
    ipServidor = config.get("IPS","ipServidor") # tcp
    ipBroadcast = config.get("IPS","ipBroadcast") # tcp
    macGateway = config.get("MACS","macGateway") #udp
    num_max_conexiones = config.getint("CONEXIONES","numeroConexiones") # tcp

    proceso = config.getint("PROCESOS","proceso") # General

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

    def paquete(self,pkt ):

        try:

            tipoPkt = pkt['ethtype']
            red = self.network
            srcip = pkt['srcip']
            protocolo = pkt['protocol']
            dstport = pkt['dstport']
            srcport = pkt['srcport']


        except:
            print "EQQQQ"



        respuesta = ""
			
        if self.proceso == 0:

			if tipoPkt == 2054:
				respuesta = arp.arp_spoofing(pkt, self.ListaARP)

			elif tipoPkt == 2048:				
				respuesta = ip.ip_spoofing(pkt,  self.IpMac, self.Paquete, self.lstSrcMac, self.lstMacAtacante, self.ipGateway)
				if respuesta == "LAN":
					if protocolo == 6:
						respuesta = tcp.tcp_syn_flood(pkt, self.ListaAtacantes, self.ListaClientes, self.ListaSolicitudes, self.IpNumSOLT, self.IpNumCLIT, self.ipServidor, self.num_max_conexiones, self.tamano_max_listasolicitudes)
						if respuesta == "LAN":							
							if dstport == 443 or srcport == 443:
								respuesta = https.thc_ssl_dos(red, pkt, self.ListaAtacantesT, self.ListaClientesT, self.ListaSolicitudesT, self.IpNumC, self.IpNumS)
							else:
								respuesta = "LAN"
					elif protocolo == 17:
						respuesta = udp.dns_spoofing(pkt, red, self.ListaAtacantesDNS, self.macGateway)
						
					elif protocolo == 1:
						respuesta = icmp.smurf(pkt)				
			else:
				print "Paquete desconocido"
				respuesta = "LAN"

        elif self.proceso == 1:
            if tipoPkt == 2054:
				respuesta = arp.arp_spoofing(pkt, self.ListaARP)
            else :
                respuesta = "LAN"

        elif self.proceso == 2:

			if tipoPkt == 2048:
				respuesta = ip.ip_spoofing(pkt,  self.IpMac, self.Paquete, self.lstSrcMac, self.lstMacAtacante, self.ipGateway)
			else:
				respuesta = "LAN"
        elif self.proceso == 3:
            try:
                if tipoPkt == 2048 and protocolo == 6:
                    respuesta = tcp.tcp_syn_flood(pkt, self.lstAtacantesT, self.dicSolicitudesT, self.dicClientesT, self.ipServidor, self.num_max_conexiones)
                else:
                    if (srcip in self.lstAtacantesT):
                        respuesta  = "HONEYNET"
                    else:
                        respuesta = "LAN"
            except:
                print("ERROR TCP")
        elif self.proceso == 4:
            if tipoPkt == 2048 and protocolo == 17:
                respuesta = udp.dns_spoofing(pkt, red, self.ListaAtacantesDNS, self.macGateway)
            else:
				respuesta = "LAN"
        elif self.proceso == 5:
			if tipoPkt == 2048 and protocolo == 1:
				respuesta = icmp.smurf(pkt, IP(self.ipBroadcast))
			else:
				respuesta = "LAN"
				
        if self.proceso == 6:
            try:
                if tipoPkt == 2048 and (dstport == 443 or srcport == 443):
                    respuesta = https.thc_ssl_dos(pkt, self.lstAtacantesS, self.dicSolicitudesS, self.dicClientesS, self.ipServidor, self.num_max_conexiones)
                else:
                    if (srcip in self.lstAtacantesS):
                            respuesta  = "HONEYNET"
                    else:
                            respuesta = "LAN"
            except:
                print "ERROR HTTPS"
        if respuesta == "LAN":
            enviar.enviar_paquete(pkt, red, self.puertoHoneynet)
        elif respuesta == "HONEYNET":
            enviar.enviar_Honeynet(pkt, red, self.puertoHoneynet)
				
def main():
	return ControladorHoneynet()

