###################################################################################
# ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################



from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
import socket
import binascii
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



def enviar_RARP(paquete, network):
    config = ConfigParser()
    #config.read("honeynet.cfg") #Se ha creado una instancia de la clase ConfigParser que nos permite  leer un archivo de configuracion
    puertoHoneynet = config.get("PUERTOS", "puertoHoneynet")
    """Construct an arp packet from scratch and send"""
    print "Ejecutando senvio de paquete.."
    switchh = paquete['switch']
    portin = paquete['inport']
    rp = Packet()
    rp = paquete
    rp = rp.modify(dstmac="FF:FF:FF:FF:FF:FF")
    rp = rp.modify(dstip="0.0.0.0")
    rp = rp.modify(srcip="0.0.0.0")
    rp = rp.modify(ethtype=32821)
    rp = rp.modify(protocol=3)
    #print rp
    for port in network.topology.egress_locations() - {Location(switchh, portin)} - {
        Location(switchh, int(puertoHoneynet))}:
        puerto = port.port_no
        rp = rp.modify(outport=puerto)
        network.inject_packet(rp)


def enviar_ARP(paquete, network):
    config = ConfigParser()
    config.read(
        "honeynet.cfg")  #Se ha creado una instancia de la clase ConfigParser que nos permite  leer un archivo de configuracion
    puertoHoneynet = config.get("PUERTOS", "puertoHoneynet")
    """Construct an arp packet from scratch and send"""
    print "Ejecutando senvio de paquete.."
    rp = Packet()
    macsrc = paquete['srcmac']
    ipsrc = paquete['srcip']
    hexipsrc = binascii.hexlify(socket.inet_aton(str(ipsrc)))
    ipdst = paquete['dstip']
    hexipdst = binascii.hexlify(socket.inet_aton(str(ipdst)))
    switchh = paquete['switch']
    portin = paquete['inport']
    rp = rp.modify(dstmac="FF:FF:FF:FF:FF:FF")
    rp = rp.modify(srcmac=macsrc)
    rp = rp.modify(dstip=ipdst)
    rp = rp.modify(srcip=ipsrc)
    rp = rp.modify(ethtype=2054)
    rp = rp.modify(protocol=1)
    rp = rp.modify(switch=switchh)
    rp = rp.modify(header_len=14)
    rp = rp.modify(payload_len=28)
    rp = rp.modify(inport=portin)
    a = "FFFFFFFFFFFF" + hexMAC(str(macsrc)) + "08060001080006040001" + hexMAC(
        str(macsrc)) + hexipsrc + "000000000000" + hexipdst
    rp = rp.modify(raw=binascii.unhexlify(a))
    #print rp
    for port in network.topology.egress_locations():
        puerto = port.port_no
        rp = rp.modify(outport=puerto)
        network.inject_packet(rp)


def hexMAC(campo):
    a = campo.split(':')
    b = a[0] + a[1] + a[2] + a[3] + a[4] + a[5]
    return b


def enviar_DNS(paquete, network):
    try:
        rp = Packet()
        rp = paquete
        rp = rp.modify(dstip="8.8.8.8")
        #print rp
        network.inject_packet(rp)
        print "Paquete enviado exitosamente!!..."

    except:
        print "Error al enviar el paquete..."
