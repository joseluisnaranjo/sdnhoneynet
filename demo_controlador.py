###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################
#Nuevo comentario
import collections
import syn_flood
import enviar
import demo_protocolo_ip
import demo_protocolo_arp
import dns_spoofing
from pyretic.lib.corelib import *
from pyretic.lib.std import *

from pyretic.lib.query import *
from ConfigParser import ConfigParser
import os
import binascii
import socket


class ControladorHoneynet(DynamicPolicy):
    IpMac = {}
    lstMacAtacante = []
    lstSrcMac = []
    Paquete = Packet()
    num = 0
    config = ConfigParser()
    config.read("honeynet.cfg")


    print "Ejecutando la aplicacion para el controlador de la Honeynet... "
    def __init__(self):
        print "Se iniciara el constructor de la clase.."

        # Se ha creado una instancia de la clase ConfigParser que nos permite  leer un archivo de configuracion
        IpMac = {}
        IpPaquete = {}
        ListaSolicitudes = []
        ListaAtacantes = []
        ListaClientes = []
        ListaRARP = []
        ListaDNS = []
        paqueteARP = Packet()


        self.query = packets()
        self.remotes_ip = {}
        self.query.register_callback(self.paquete)
        self.network = None
        super(ControladorHoneynet, self).__init__(self.query)
        print "Ha terminado la ejecucion del constructor.."

    def set_network(self, network):
        self.network = network

    def paquete(self, pkt):
        try:
            tipoPkt = pkt['ethtype']
            red = self.network
            switch = pkt['switch']

        except:
		    print "%%%%%%%%%%%%%%%%%%%%"


        if tipoPkt == 2054:

             demo_protocolo_arp.manejadorArp(pkt, red, switch)

        elif tipoPkt == 2048:
            demo_protocolo_ip.manejadorIp(pkt, red, self.IpMac, self.Paquete, self.lstSrcMac, self.lstMacAtacante)
        else:
            manejadorProtocolos(pkt, red, switch)

        print "se ha recibido el paquete numero = " + str(self.num)


def main():
	#print "Ejecutando main.."
	return ControladorHoneynet()


def manejadorProtocolos(pkt):
    print "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%"
    print "Paquetes desconocidos "
    inport = pkt['inport']
    print "puerto entrada = " + str(inport)
    print "???????????????????????????????????????????????"

