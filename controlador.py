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
    IpNum = {}
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
				
			if (verificacionCompleta):		

				if tipoPkt == 2054:
					arp.arp_spoofing(pkt, red)				

				elif tipoPkt == 2048:				
					proceso = ip.ip_spoofing(pkt,  self.IpMac, self.Paquete, self.lstSrcMac, self.lstMacAtacante)
					if proceso == "TCP":
						if protocolo == 6:
							proceso = tcp.tcp_syn_flood(pkt, self.ListaAtacantes, self.ListaClientes, self.ListaSolicitudes, self.IpNum )
							if proceso== "THC":
								print("llamar al archivo ssl")
								if dstport == 443 or srcport == 443:
									https.thc_ssl_dos(red, pkt, self.ListaAtacantesT, self.ListaClientesT, self.ListaSolicitudesT, self.IpNumC, self.IpNumS)
								else:
									enviar.enviar_paquete(pkt, red)
							elif proceso == "HONEYNEY":
								print("enviar al honeynet")
								enviar.enviar_Honeynet(pkt, red)
						else:
							enviar.enviar_paquete(pkt, red)
					elif proceso == "UDP":
						print("llamar al dns_spoofing")
						udp.dns_spoofing(pkt, red)
					elif proceso == "ICMP":
						icmp.smurf(pkt, red)						
					elif proceso == "HONEYNET":
						print("enviar al honeynet")
						enviar.enviar_Honeynet(pkt, red)
					
				else:
					print "Paquete desconocido"
			if (verificarArp):
				if tipoPkt == 2054:
					arp.arp_spoofing(pkt, red)
				else :
					envia.enviar_paquete(pkt, red)
			if (verificarIP):
				proceso = ip.ip_spoofing(pkt,  self.IpMac, self.Paquete, self.lstSrcMac, self.lstMacAtacante)
				if proceso == "HONEYNET":
					enviar.enviar_Honeynet(pkt, red)
				else:
					envia.enviar_paquete(pkt, red)
			if(verificarIcmp):
			
			if (verificarUdp):
				udp.dns_spoofing(pkt, red)
			if (verificarTcp):
				proceso = tcp.tcp_syn_flood(pkt, self.ListaAtacantes, self.ListaClientes, self.ListaSolicitudes, self.IpNum )
				if proceso == "HONEYNEY":
					print("enviar al honeynet")
					enviar.enviar_Honeynet(pkt, red)
				else:
					envia.enviar_paquete(pkt, red)
			if (verificarHttps):
				https.thc_ssl_dos(red, pkt, self.ListaAtacantesT, self.ListaClientesT, self.ListaSolicitudesT, self.IpNumC, self.IpNumS)
				
					
				
				
				
				
				
def main():
	return ControladorHoneynet()

