###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################


import enviar
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *


def enviar_paquete(paquete,network,outport):
	"""Construct an arp packet from scratch and send"""
	print "Ejecutando senvio de paquete.."
	rp = Packet()
	rp = paquete
	rp = rp.modify(outport = outport)
	print rp
	network.inject_packet(rp)
