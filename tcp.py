###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

import collections
from ConfigParser import ConfigParser


def tcp_syn_flood(pkt, lstAtacantes, dicSolicitudes, dicClientes, ipServidor, num_max_conexiones):
	srcip = ""
	try :
		tipoPkt = pkt['ethtype']
		protocolo = pkt['protocol']
		srcip = pkt['srcip']
	except:
		print "Error"
	tcp_flags = payload(pkt, 94, 96)
	respuesta = ""
	
	if tipoPkt == 2048 and protocolo == 6:
		if ipServidor == srcip:
			respuesta = "LAN"
		else:
			if str(tcp_flags) == "02":
				if srcip in lstAtacantes:
					respuesta  = "HONEYNET"

				else:
					if dicSolicitudes.has_key(srcip):
						if dicSolicitudes[srcip] < num_max_conexiones:
							dicSolicitudes[srcip] = dicSolicitudes[srcip] + 1
							respuesta  = "LAN"
						else:
							del dicSolicitudes[srcip]
							lstAtacantes.append(srcip)
							respuesta  = "HONEYNET"

						
					else:
						if dicClientes.has_key(srcip):
							if dicClientes[srcip] < num_max_conexiones:
								dicClientes[srcip] = dicClientes[srcip] + 1
								respuesta  = "LAN"
							else:
								del dicClientes[srcip]
								lstAtacantes.append(srcip)
								respuesta  = "HONEYNET"

						else:
							dicSolicitudes[srcip] = 1
							respuesta  = "LAN"

			else:
				if str(tcp_flags) == "10":
					if dicSolicitudes.has_key(srcip):
						del dicSolicitudes[srcip]
						dicClientes[srcip] = 1
						respuesta  = "LAN"
					else:
						if srcip in lstAtacantes:
							 lstAtacantes.remove(srcip)
							 dicClientes[srcip] = 1
							 respuesta  = "LAN"
						else:
							if dicClientes.has_key(srcip):
								if dicClientes[srcip] >= 0:
									dicClientes[srcip] = dicClientes[srcip] - 1									
								respuesta  = "LAN"								

				else:
					if srcip in lstAtacantes:
						respuesta  = "HONEYNET"
					else:
						respuesta  = "LAN"
	else:
		if (srcip in lstAtacantes):
			respuesta  = "HONEYNET"
		else:
			respuesta = "LAN"
	return respuesta
	
	

def payload(pkt,num1,num2):
    of_payload_code = pkt['raw']
    of_payload = of_payload_code.encode("hex")
    bandera = of_payload[num1:num2]
    return bandera

	
#Clase terminada  completamente... Revisar!!!!
