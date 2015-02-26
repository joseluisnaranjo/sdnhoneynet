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
ListaSolicitudes = []
ListaAtacantes = []
ListaClientes = []

def syn_flood(pkt, network, IpPuerto):

	#paquete TCP
	print "Se ha recibido un paquete TCP"
	tcp_flags = payload(pkt,94,96)
	dstport = payload(pkt,74,78)
	srcport = payload(pkt,70,74)
	ssl_flags = payload(pkt,120,122)
	ssl_datos 
	if (dstport == 0443):
		print ssl_flags
		comprobarFlags(pkt,network,IpPuerto,ssl_flags,"01","LL")
	elif (srcport == 0443):
		comprobarFlags(pkt,network,IpPuerto,ssl_flags,"LL","23")
	else:
		print tcp_flags
		comprobarFlags(pkt,network,IpPuerto,tcp_flags,"02","10")
	
	
	
def comprobarFlags(pkt,network,IpPuerto,flag,flagInicial,flagFinal):	
	switch = pkt['switch']
	inport = pkt['inport']
	srcip  = pkt['srcip']        
	dstip  = pkt['dstip']        
	opcode = pkt['protocol']
	#Se obtiene  de un archivo de configuracion la ip del servidor 
	ipServidor = config.get("SYNFLOOD","ipServidor")
	#A continuacion se verifica si se trata de una peticion (SYN)
	if flag == flagInicial:
		#A continuacion se obtiene el tamano de la lista de solicitudes para limitar el numero de solicitudes permitidas
		tamano_actual_listasolicitudes = len(ListaSolicitudes)
		#Se obtiene  de un archivo de configuracion el tamano maximo que puede tener la lista de Solicitudes de conexion TCP que ha recibido el servidor 
		tamano_max_listasolicitudes = config.get("SYNFLOOD","tamano")
		#A continuacion se verifica que el tamano de la lsiat sea menor al maximo especificado en el archivo de configuracion
		if tamano_actual_listasolicitudes < tamano_max_listasolicitudes:
			#A continuacion se verifica que la direccion IP origen del segmento TCP recibido no sea la del servidor
			if srcip == ipServidor:
				#En caso que la direccion  Ip de origen es la del servidor, el trafico se debe deja pasar sin ninguna restriccion
				enviar.enviar_paquete(pkt,network,IpPuerto[dstip])										
							
			else:
				#A continuacion se verifica que la direccion IP origen del segmento TCP recibido no se encuentre en la lista de solicitudes
				if srcip in ListaSolicitudes:
					#Si la direccion IP origen del segmento TCP recibido SI se encuentre en la lista de solicitudes, entonces se procede a borrarla de dicha lista y,
					ListaSolicitudes.remove(srcip)
					# Se la agrega a la lista de Atacantes, puesto que se presume  esta intentando hacer un segundo intento de conexion al servidor al mismo timpo..
					ListaAtacantes.append(srcip)
					#Sin embargo se deja pasar un solo paquete paga obtener estadisticas
					print "Revisar siguiente linea no se debe enviar todos los paquetes..."
					enviar.enviar_paquete(pkt,network,IpPuerto[dstip])								
																					
				else:
					#A continuacion se verifica que la direccion IP origen del segmento TCP recibido  se encuentre en la lista de atacantes
					if srcip in ListaAtacantes:
						#Se envia el paquete a la honeynet 
						print "Revisar  a donde se envia el paquete!!!"
						enviar.enviar_paquete(pkt,network,IpPuerto[dstip])		

					else:
						#A continuacion se verifica que la direccion IP origen del segmento TCP recibido se encuentre en la lista de Clientes lejitimos
						if srcip in ListaClientes:
							enviar.enviar_paquete(pkt,network,IpPuerto[dstip])									

						else:	
							#Debido a que no estaba en al lista de clientes lejitimos, se procede a anadirla
							ListaSolicitudes.append(srcip)
							#Se verifica que efectivamente  se haya anadido a la lista 
							if ListaSolicitudes[-1] == srcip:
								enviar.enviar_paquete(pkt,network,IpPuerto[dstip])
							else:
								print "Error al anadir  a la lista..."							
						

		else:
			#En caso de que el tamano de la lista sea mayor al tamano maximo especificado, Se anade a la lista de atacantes la primera solicitud que se agrego a la lista de solicitudes pendientes 
			ListaAtacantes.append(ListaSolicitudes[0])
			# A continuacion se procede a borrar la solicitud que se ha enviado a la lista de atacantes  de la lista de solicitudes para liberar un espacio
			del ListaSolicitudes[0]
			# Y finalmente se agrega la nueva solicitud a la lista de solicitudes pendientes 
			ListaSolicitudes.append(srcip)
	#A continuacion se verifica si se trata de una respuesta a la peticion (ack) (tercera via de la conexion TCP)
	elif flag == flagFinal:					
		#A continuacion se verifica si la direccion ip origen es la direccion del servidor 
		if srcip == ipServidor:
			#Se envia el paquete sin ninguna restriccion 
			enviar.enviar_paquete(pkt,network,IpPuerto[dstip])
						
		else:
			#A continuacion se verifica si la direccion ip de origen se encuentra en la lista de solicitudes
			if srcip in ListaSolicitudes:
				#Se procede a enviar el paquete, ya que se concidera una conexion legitima 
				enviar.enviar_paquete(pkt,network,IpPuerto[dstip])
				#Ya que es una conexion lejitima se procede a eliminar de la lista de solicitudes y
				ListaSolicitudes.remove(srcip)
				#Se le anade a la lista de clientes legitimos
				ListaClientes.append(srcip)
				#A continuacion se verifica  si la direccion IP origen  esta en la lista de atacantes aun caundo se trata de uan conexion legitima (lenta) debido a que se revico la tercera via TCP.
			elif srcip in ListaAtacantes:
				#Se  procede a enviar el paquete 
				enviar.enviar_paquete(pkt,network,IpPuerto[dstip])
				#Se la remueve de la lista de atacantes 
				ListaAtacantes.remove(srcip)
				#Se la agrega a la lsita de clientes legitimos.
				ListaClientes.append(srcip)
			else:
				#Se trata de uan conexxion legitima por lo que se envia el paquete sin ninguna restriccion.
				enviar.enviar_paquete(pkt,network,IpPuerto[dstip])					
				
	else:
		#Cualquier otra bandera que se envia no se la analiza en este proyecto por lo que se envia el paquete sin niguna restriccion.
		enviar.enviar_paquete(pkt,network,IpPuerto[dstip])
		
def payload(pkt,num1,num2):	
	of_payload_code = pkt['raw']
	#A continucaion se codifica en hexadecimal dicho payload
	of_payload = of_payload_code.encode("hex")
	#A continuacion se  extrae alguas bandetas de TCP, aquellas que nos indican si es syn, syn-ack y ack  
	return of_payload[num1:num2]			
		
