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
import arp
import syn_flood
import enviar
import dns_spoofing
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from ConfigParser import ConfigParser
import os
import binascii
import socket
class ManejoIP():

	config = ConfigParser()
	#config.read("honeynet.cfg") #Se ha creado una instancia de la clase ConfigParser que nos permite  leer un archivo de configuracion
	puertoHoneynet = config.get("PUERTOS","puertoHoneynet")

	ListaSolicitudes = []
	ListaAtacantes = []
	ListaClientes = []
	IpMac = {}

	num = 0
	

	print "Ejecutando la aplicacion para el controlador de la Honeynet... "

	def __init__(self):

		print "Se iniciara el constructor de la clase.."
		self.query = packets()
		self.ListaSolicitudes = []
		self.ListaAtacantes = []
		self.ListaClientes = []
		self.IpMac = {}
	
		print "Ha terminado la ejecucion del constructor.."



	def manejoPaquete(self,pkt):

            inport = pkt['inport']
            if self.num < 100:
                if inport != int(self.puertoHoneynet):
                    a = self.network
                    b = int(self.puertoHoneynet)
                    #c = self.num
                    ejecucion(pkt, a,b, self.num)
		    print "se a recibido el paquete numero = " + str(self.num)
            else:
		    a = self.network                    
                    b = 1
                    ejecucion(pkt, a, b, self.num)
		    print "se a recibido el paquete numero = " + str(self.num)


	def ejecucion(pkt):

	
	    if srcip in ListaSolicitudes:
	    if (self.IpMac[srcip] == ''):
		self.IpMac[srcip] = srcmac
		print "Se a  recibido un pauqete de un ciente nuevo..."
	    else
		(self.IpMac[srcip] == srcmac)
		print "Elpaquete recibido  es de un cliente conocido..."
	    
