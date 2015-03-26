###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

import collections
import enviar
import os
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

from ConfigParser import ConfigParser

config = ConfigParser()
config.read("honeynet.cfg")

def manejadorArp(pkt, red, switch):
    print "paquete arp"
    inport = pkt['inport']
    for port in red.topology.egress_locations() - {Location(switch, inport)}:
        puerto = port.port_no
        print "puerto entrada = " + str(inport)
        print "puerto switch = " + str(puerto)
        enviar.enviar_paquete(pkt,red,puerto)
        print "****************************************"
