###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

import enviar
from ConfigParser import ConfigParser

config = ConfigParser()
config.read("honeynet.cfg")

def manejadorArp(pkt, red):
    print "paquete arp"
    enviar.enviar(pkt,red)
    print "****************************************"
