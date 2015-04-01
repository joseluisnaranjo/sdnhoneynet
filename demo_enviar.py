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


def enviar_paquete(paquete, network):
    config = ConfigParser()
    config.read("honeynet.cfg")
    puertoHoneynet = config.get("PUERTOS", "puertoHoneynet")
    switch = paquete['switch']
    inport = paquete['inport']
    for port in network.topology.egress_locations() - {Location(switch, inport)} - {Location(switch, int(puertoHoneynet))}:
        puerto = port.port_no
        paquete = paquete.modify(outport=puerto)
        network.inject_packet(paquete)


def enviar_Honeynet(paquete, network):
    config = ConfigParser()
    config.read("honeynet.cfg")
    puertoHoneynet = config.get("PUERTOS", "puertoHoneynet")
    switch = paquete['switch']
    paquete = paquete.modify(outport=int(puertoHoneynet))
    network.inject_packet(paquete)
    print "Paquete enviado  a al HONEYNET exitosamente!!..."



#Prohibido Modificar
def send(rp,network):
    for port in network.topology.egress_locations():
        puerto = port.port_no
        rp = rp.modify(outport=puerto)
        network.inject_packet(rp)
        print "Paquete enviado exitosamente!!..."
