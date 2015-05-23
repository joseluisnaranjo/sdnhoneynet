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

def enviar_Honeynet(paquete, network, puertoHoneynet):

    switch = paquete['switch']
    paquete = paquete.modify(outport=puertoHoneynet)
    network.inject_packet(paquete)
    print "Paquete enviado a al HONEYNET exitosamente!!..."

#Prohibido Modificar
def send(rp,network):
    for port in network.topology.egress_locations():
        puerto = port.port_no
        rp = rp.modify(outport=puerto)
        network.inject_packet(rp)
        print "Paquete enviado exitosamente!!..."

def enviar(paquete,network):
    config = ConfigParser()
    config.read("honeynet.cfg")
    puertoHoneynet = config.getint("PUERTOS", "puertoHoneynet")
    puertoLan = config.getint("PUERTOS", "puertoLan")
    switch = paquete['switch']
    inport = paquete['inport']
    for port in network.topology.egress_locations() - {Location(switch, inport)}:
        outport = port.port_no
        if (((inport != puertoLan) or (outport != puertoHoneynet)) and ((inport != puertoHoneynet) or (outport != puertoLan))):
            paquete = paquete.modify(outport=outport)
            network.inject_packet(paquete)
            print "Paquete enviado exitosamente!!..."