###################################################################################
# ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

from pyretic.lib.corelib import *
from ConfigParser import ConfigParser

def enviar_paquete(paquete, network, puertoHoneynet):

    switch = paquete['switch']
    inport = paquete['inport']

    for port in network.topology.egress_locations() - {Location(switch, inport)} - {Location(switch, puertoHoneynet)}:
        puerto = port.port_no
        paquete = paquete.modify(outport=puerto)
        network.inject_packet(paquete)
        print "Paquete enviado a la LAN!!..."

def enviar_Honeynet(paquete, network, puertoHoneynet):
    paquete = paquete.modify(outport=puertoHoneynet)
    network.inject_packet(paquete)
    print "Paquete enviado a la HONEYNET !!..."


def send(pkt,network, puerto):
        rp = pkt.modify(outport=puerto)
        network.inject_packet(rp)
        print "Paquete enviado a la LAN!!..."
