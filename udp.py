###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

import enviar
from ConfigParser import ConfigParser

config = ConfigParser()
config.read("honeynet.cfg") #Se ha creado una instancia de la clase ConfigParser que nos permite  leer un archivo de configuracion

def dns_spoofing(pkt,red,ListaAtacanteDNS):
	srcmac = pkt['srcmac']
    macGateway = config.get("DNS_Spoofing","macGateway")
	
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
				enviar.enviar_paquete(pkt, red)
			else:
				ListaAtacantes.append(srcmac)
				enviar.enviar_Honeynet(pkt, red)
		else:
			enviar.enviar_paquete(pkt, red)
