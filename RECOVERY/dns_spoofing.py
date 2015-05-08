###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

import collections
import enviar
from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from ConfigParser import ConfigParser

config = ConfigParser()
config.read("honeynet.cfg") #Se ha creado una instancia de la clase ConfigParser que nos permite  leer un archivo de configuracion

def dns_spoofing(pkt,network,IpPuerto,identificador,lenURL,ListaDNS):
	dstip  = pkt['dstip']
	ipServidorDNS = config.get("DNS_Spoofing","ipServidorDNS")
	dns_flags=payload(pkt,90,93)
	lenPayload = len(pkt['raw'].encode("hex"))
	#Se comprueba si es una pregunta dns al comprobar el contenido de su bandera
	if (dns_flags == 0100):
		if (dstip == ipServidorDNS):
			enviar.enviar_paquete(pkt,set_network,IpPuerto[dstip])
						
		else:
			enviar.enviar_paquete(pkt,set_network,IpPuerto[dstip])
			enviar.enviar_DNS(pkt,network)
			identificador=payload(pkt,86,89)
			lenURL = len(payload(pkt,110,lenPayload-9))
	#En caso de que sea una respuesta, que ip corresponde al dominio preguntado
	elif (dns_flags == 8180):
		idRespuestas = payload(pkt,86,89)
		if (idRespuestas == identificador):
			#Lista en el que se guardaran todas las respuestas DNS
			ListaDNS.append(pkt)
			#Tiempo que esperara a que lleguen todas las respuestas DNS
			tiempo = config.get("DNS_Spoofing","tiempo")
			time.sleep(tiempo)
			num = 0
			while (num < 2):
				#A continuacion se  extrae la ip que se envia como respuesta del dns 
				ubicacion = lenURL + 142

				'''
				ipS_Respuestas = payload(pkt,ubicacion,lenPayload-1)
				cadenaRespuestas = ipS_Respuestas.split('00010001')
				fila=0
				for ip_Respuesta in cadenaRespuestas:
					ipRespuesta[num][fila]=ip_Respuesta[14:21]
					fila=fila+1
				'''	
				ip_Respuesta[num] = payload(ListaDNS[num],ubicacion,lenPayload-1)	
								
				num = num + 1
			
			if (ip_Respuesta[0] == ip_Respuesta[1]):
				enviar.enviar_paquete(pkt,network,IpPuerto[dstip])
			else:
				num = 0
				while(num < 2):
					if ListaDNS[num]['srcip'] != IPAddr('8.8.8.8'):
						enviar.enviar_paquete(ListaDNS[num],network,IpPuerto[dstip])
					num = num + 0	
		else:
			enviar.enviar_paquete(pkt,network,IpPuerto[dstip])	
			
def payload(pkt,num1,num2):	
	of_payload_code = pkt['raw']
	#A continucaion se codifica en hexadecimal dicho payload
	of_payload = of_payload_code.encode("hex")
	#A continuacion se  extrae alguas bandetas de TCP, aquellas que nos indican si es syn, syn-ack y ack  
	return of_payload[num1:num2]			
	
