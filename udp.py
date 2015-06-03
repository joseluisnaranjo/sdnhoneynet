###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

import enviar

def dns_spoofing(pkt, ListaAtacantesDNS, macGateway):
    dstmac = pkt['dstmac']
    srcmac = pkt['srcmac']

    of_payload_code = pkt['raw']
    	#A continucaion se codifica en hexadecimal dicho payload
    of_payload = of_payload_code.encode("hex")
    	#A continuacion se  extrae alguas bandetas de TCP, aquellas que nos indican si es syn, syn-ack y ack
    dns_flags = of_payload[54:100]

    if srcmac in ListaAtacantesDNS:
		respuesta = "HONEYNET"
    else:
		if (dns_flags == 0100):
			if dstmac ==  macGateway:
				respuesta = "LAN"
			else:
				ListaAtacantesDNS.append(dstmac)
				respuesta = "HONEYNET"
		else:
			respuesta = "LAN"
    return respuesta