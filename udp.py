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
	respuesta = ""

    dns_flags = payload[96:100]

	if (dns_flags != 0000):
	#si es respuesta 
		if srcmac ==  macGateway:
			respuesta = "LAN"
		else:
			if srcmac in ListaAtacantesDNS:
				respuesta = "HONEYNET"
			else:
				ListaAtacantesDNS.append(srcmac)
				respuesta = "HONEYNET"
	else:
	#si es pregunta
		respuesta = "LAN"
			
    return respuesta

	
def payload(pkt,num1,num2):
    of_payload_code = pkt['raw']
    of_payload = of_payload_code.encode("hex")
    return of_payload[num1:num2]