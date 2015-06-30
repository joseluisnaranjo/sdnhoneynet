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
	
    dicSolicitudesA = {}
    dicMacIpA = {}
    dicMacPuertoA = {}
    ListaAtacantesA = []

    dicIpMacI = {}
    dicMacPuertoI = {}
    lstMacAtacanteI = []

    dicSolicitudesT = {}    
    dicClientesT = {}
	lstAtacantesT = []

    dicSolicitudesS = {}    
    dicClientesS = {} 
	lstAtacantesS = []

    ListaAtacantesU = [] 


    puertoHoneynet = config.getint("PUERTOS", "puertoHoneynet")
    ipServidor = config.get("IPS","ipServidor") 
    ipBroadcast = config.get("IPS","ipBroadcast")
    macGateway = config.get("MACS","macGateway")
    num_max_permitido = config.getint("CONEXIONES","numeroConexiones") 
    proceso = config.getint("PROCESOS","proceso")


    def __init__(self):	
		print "Se iniciara el constructor de la clase.."
		self.query = packets()
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
			respuesta = arp.arp_spoofing(pkt, self.dicSolicitudesA, self.dicMacIpA,self.dicMacPuertoA, self.ListaAtacantesA)
			if respuesta == "LAN":			
				respuesta = ip.ip_spoofing(pkt,  self.dicIpMacI, self.dicMacPuertoI, self.lstMacAtacanteI, self.puertoHoneynet)
				if respuesta == "LAN":
					respuesta = tcp.tcp_syn_flood(pkt, self.lstAtacantesT, self.dicSolicitudesT, self.dicClientesT, IP(self.ipServidor), self.num_max_permitido)
					if respuesta == "LAN":
						respuesta = udp.dns_spoofing(pkt, self.ListaAtacantesU, MAC(self.macGateway))				
						if respuesta == "LAN":
							respuesta = icmp.smurf(pkt, IP(self.ipBroadcast))
							if respuesta == "LAN":		
							    respuesta = https.thc_ssl_dos(pkt, self.lstAtacantesS, self.dicSolicitudesS, self.dicClientesS, IP(self.ipServidor), self.num_max_permitido)
             


        elif self.proceso == 1:
            respuesta = arp.arp_spoofing(pkt, self.dicSolicitudesA, self.dicMacIpA, self.dicMacPuertoA, self.ListaAtacantesA)


        elif self.proceso == 2:
			respuesta = ip.ip_spoofing(pkt,  self.dicIpMacI, self.dicMacPuertoI, self.lstMacAtacanteI, self.puertoHoneynet)


        elif self.proceso == 3:
            respuesta = tcp.tcp_syn_flood(pkt, self.lstAtacantesT, self.dicSolicitudesT, self.dicClientesT, IP(self.ipServidor), self.num_max_permitido)
               

        elif self.proceso == 4:
            respuesta = udp.dns_spoofing(pkt, self.ListaAtacantesU, MAC(self.macGateway))


        elif self.proceso == 5:
			respuesta = icmp.smurf(pkt, IP(self.ipBroadcast))
			
			
        elif self.proceso == 6:
            respuesta = https.thc_ssl_dos(pkt, self.lstAtacantesS, self.dicSolicitudesS, self.dicClientesS, IP(self.ipServidor), self.num_max_permitido)
                      


        if respuesta == "LAN":
            enviar.enviar_Lan(pkt, red, self.puertoHoneynet)
        elif respuesta == "HONEYNET":
            enviar.enviar_Honeynet(pkt, red, self.puertoHoneynet)
        elif respuesta == "TODO":
            enviar.enviar_Todo(pkt, red)
        elif respuesta == "ATACANTE":
            enviar.enviar_Honeynet(pkt, red, self.dicMacPuertoI[dstmac])


def main():
	return ControladorHoneynet()

