###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################



from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *


def enviar_paquete(paquete,network,sending_port):
	try:
		"""Construct an arp packet from scratch and send"""
		print "Ejecutando senvio de paquete.."
		rp = Packet()
		rp = paquete
		rp = rp.modify(outport = sending_port)
		print rp
		network.inject_packet(rp)
		print "Paquete enviado exitosamente!!..."
		
	except:
		print "Error al enviar el paquete..."

def enviar_RARP(paquete,network,srcmac):
	"""Construct an arp packet from scratch and send"""
	print "Ejecutando senvio de paquete.."
	rp = Packet()
	rp = paquete
	rp = rp.modify(dstmac = "FF:FF:FF:FF:FF:FF")
	rp = rp.modify(srcmac = srcmac)
	rp = rp.modify(dstip = "0.0.0.0")
	rp = rp.modify(srcip = "0.0.0.0")
	rp = rp.modify(ethtype = 32821)
	rp = rp.modify(protocol = 3)
	
	#print rp
	for port in network.topology.egress_locations() - {Location(switch,inport)}:
		puerto = port.port_no
		#print "puerto: %d" % (puerto)
		if 3 != puerto:
			rp = rp.modify(outport = puerto)
			network.inject_packet(rp)
	
def enviar_DNS(paquete,network):
	try:
		rp = Packet()
		rp = paquete
		rp = rp.modify(dstport = "8.8.8.8")
		print rp
		network.inject_packet(rp)
		print "Paquete enviado exitosamente!!..."
		
	except:
		print "Error al enviar el paquete..."