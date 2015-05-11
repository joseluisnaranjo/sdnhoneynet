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
    ListaSolicitudes = [] # tcp
    ListaAtacantes = [] # tcp
    ListaClientes = [] # tcp
    ListaSolicitudesT = []
    ListaAtacantesT = []
    ListaClientesT = []
    ListaARP = [] # arp
    ListaDNS = []
    IpNumSOLT = {}
    IpNumCLIT = {}
    IpNum = {}
    paqueteARP = Packet()
    identificador = ""
    lenURL = 0
    num = 0
<<<<<<< HEAD
    puertoHoneynet = config.get("PUERTOS","puertoHoneynet") 
	ipGateway = config.get("IPS","ipGateway") #ip
	ipServidor = config.get("IPS","ipServidor") # tcp
	num_max_conexiones = config.get("CONEXIONES","numeroConexiones") # tcp
	tamano_max_listasolicitudes = config.get("LISTAS","tamano_max_listasolicitudes") # tcp
=======
    puertoHoneynet = config.get("PUERTOS","puertoHoneynet")
    ipServidor = config.get("SYNFLOOD", "ipServidor")
    tamano_max_listasolicitudes = config.get("SYNFLOOD", "tamano")
    proceso = config.get("PROCESOS","proceso")
>>>>>>> origin/master
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
			
        if proceso == 0:

			if tipoPkt == 2054:
				respuesta = arp.arp_spoofing(pkt, ListaARP)				

			elif tipoPkt == 2048:				
				respuesta = ip.ip_spoofing(pkt,  self.IpMac, self.Paquete, self.lstSrcMac, self.lstMacAtacante, self.ipGateway)
				if respuesta == "LAN":
					if protocolo == 6:
						respuesta = tcp.tcp_syn_flood(pkt, ListaAtacantes, ListaClientes, ListaSolicitudes, IpNumSOLT, IpNumCLIT, ipServidor, num_max_conexiones, tamano_max_listasolicitudes)
						if respuesta == "LAN":							
							if dstport == 443 or srcport == 443:
								respuesta = https.thc_ssl_dos(red, pkt, self.ListaAtacantesT, self.ListaClientesT, self.ListaSolicitudesT, self.IpNumC, self.IpNumS)
							else:
								respuesta = "LAN"
					elif protocolo == 17:
						respuesta = udp.dns_spoofing(pkt, red)
						
					elif protocolo == 1:
						respuesta = icmp.smurf(pkt)				
			else:
				print "Paquete desconocido"
				respuesta = "LAN"
<<<<<<< HEAD
				
		if (proceso == 1):
			if tipoPkt == 2054:
				respuesta = arp.arp_spoofing(pkt, ListaARP)
			else :
				respuesta = "LAN"
				
=======

        if (proceso == 1):
            if tipoPkt == 2054:
                respuesta = arp.arp_spoofing(pkt, red)
            else :
                respuesta = "LAN"

>>>>>>> origin/master
		if (proceso == 2):

			if tipoPkt == 2048:
				respuesta = ip.ip_spoofing(pkt,  self.IpMac, self.Paquete, self.lstSrcMac, self.lstMacAtacante, self.ipGateway)
			else:
				respuesta = "LAN"
				
		if (proceso == 3):
			if tipoPkt == 2048 and protocolo == 6:
				respuesta = tcp.tcp_syn_flood(pkt, ListaAtacantes, ListaClientes, ListaSolicitudes, IpNumSOLT, IpNumCLIT, ipServidor, num_max_conexiones, tamano_max_listasolicitudes)
			else:
				respuesta = "LAN"
		
		if (proceso == 4):
			if tipoPkt == 2048 and protocolo == 17:
				respuesta = udp.dns_spoofing(pkt, red)
			else:
				respuesta = "LAN"
				
		if (proceso == 5):
			if tipoPkt == 2048 and protocolo == 1:
				respuesta = icmp.smurf(pkt)
			else:
				respuesta = "LAN"
				
        if (proceso == 6):
            if tipoPkt == 2048 and dstport == 443 or srcport == 443:
                respuesta = https.thc_ssl_dos(red, pkt, self.ListaAtacantesT, self.ListaClientesT, self.ListaSolicitudesT, self.IpNumC, self.IpNumS)
            else:
                respuesta = "LAN"

        if respuesta == "LAN":
            enviar.enviar_paquete(pkt)
        else respuesta == "HONEYNET":
            enviar.enviar_Honeynet(pkt)

					
				
				
				
				
				
def main():
	return ControladorHoneynet()

