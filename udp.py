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
from pyretic.lib.query import *

def dns_spoofing(pkt, ListaAtacantesDNS, macGateway):
	try:
		tipoPkt = pkt['ethtype']
		protocolo = pkt['protocol']
		dstmac = pkt['dstmac']
		srcmac = pkt['srcmac']
	except:
		return "LAN"

	respuesta = ""

	dns_flags = payload(pkt,88,92)

	if srcmac in ListaAtacantesDNS:
		respuesta = "HONEYNET"
	else:
		if tipoPkt == 2048 and protocolo == 17:
			if (dns_flags == '0100'):
			#si es respuesta
				if dstmac ==  macGateway:
					respuesta = "LAN"
				else:
					ListaAtacantesDNS.append(dstmac)
					respuesta = "FIN"
			else:
				#si es pregunta
				respuesta = "LAN"
		else:
			#si es pregunta
			respuesta = "LAN"

	return respuesta


	
def payload(pkt,num1,num2):
    of_payload_code = pkt['raw']
    of_payload = of_payload_code.encode("hex")
    return of_payload[num1:num2]
	

#Clase terminada  completamente... Revisar!!!!