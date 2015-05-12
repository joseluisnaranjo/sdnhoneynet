###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################


def dns_spoofing(pkt,red,ListaAtacanteDNS, macGateway):
	srcmac = pkt['srcmac']	
	of_payload_code = pkt['raw']
	#A continucaion se codifica en hexadecimal dicho payload
	of_payload = of_payload_code.encode("hex")
	#A continuacion se  extrae alguas bandetas de TCP, aquellas que nos indican si es syn, syn-ack y ack
	dns_flags = of_payload[90:94]

	if srcmac in ListaAtacanteDNS:
		enviar.enviar_Honeynet(pkt, red)
	else:
		if (dns_flags == 8180):
			if srcmac ==  macGateway:
				respuesta = "LAN"
			else:
				ListaAtacantes.append(srcmac)
				respuesta = "HONEYNET"
		else:
			respuesta = "LAN"
	return respuesta
