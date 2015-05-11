###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

from ConfigParser import ConfigParser

def tcp_syn_flood(pkt, ListaAtacantes, ListaClientes, ListaSolicitudes, IpNumSOLT, IpNumCLIT, ipServidor, num_max_conexiones, tamano_max_listasolicitudes):

    srcip  = pkt['srcip']
    tcp_flags = payload(pkt, 94, 96)

    if ipServidor == srcip:
        print "Paquete legitimo"
        respuesta  = "LAN"
    else:
        if str(tcp_flags) == "02":
            if srcip in ListaAtacantes:
                print "Paquete peligroso..."
                respuesta  = "HONEYNEY"

            else:
                if srcip in ListaSolicitudes:
                    if IpNumSOLT.has_key(srcip):
						if IpNumSOLT[srcip] < num_max_conexiones:
							IpNumSOLT[srcip] = IpNumSOLT[srcip] + 1
							respuesta  = "LAN"
						else:
							ListaSolicitudes.remove(srcip)
							ListaAtacantes.append(srcip)
							del IpNumSOLT[srcip]
							respuesta  = "HONEYNET"
                    else:
						IpNumSOLT[srcip] = 1
						respuesta  = "LAN"					
					
                else:
                    if srcip in ListaClientes:
                        if IpNumCLIT.has_key(srcip):
                            if IpNumCLIT[srcip] < num_max_conexiones:
                                IpNumCLIT[srcip] = IpNumCLIT[srcip] + 1
                                respuesta  = "LAN"
                            else:
                                ListaClientes.remove(srcip)
                                ListaAtacantes.append(srcip)
                                del IpNumCLIT[srcip]
                                respuesta  = "HONEYNET"
                        else:
                            IpNumCLIT[srcip] = 1
                            respuesta  = "LAN"
                    else:
                        if len(ListaSolicitudes) < tamano_max_listasolicitudes:
                            ListaSolicitudes.append(srcip)
                            print "Paquete legitimo......"
                            respuesta  = "LAN"
                        else:
                            ListaAtacantes.append(ListaSolicitudes[0])
                            del ListaSolicitudes[0]
                            ListaSolicitudes.append(srcip)
                            print "Paquete legitimo... ..."
                            respuesta  = "LAN"
        else:
            print str(tcp_flags)
            if str(tcp_flags) == "10":
                if srcip in ListaSolicitudes:
                    ListaSolicitudes.remove(srcip)
                    ListaClientes.append(srcip)
					IpNumSOLT[srcip] = IpNumSOLT[srcip] - 1
                    print "Paquete legitimo......"
                    respuesta  = "LAN"
                else:
                    if srcip in ListaAtacantes:
                         ListaAtacantes.remove(srcip)
                         ListaClientes.append(srcip)
                         print "Paquete legitimo......"
                         respuesta  = "LAN"
                    else:
						if srcip in ListaClientes:
							print "Paquete legitimo......"
							respuesta  = "LAN"
            else:
                if str(tcp_flags) == "11":
                    if srcip in ListaClientes:
                        if IpNumCLIT.has_key(srcip):
                            IpNumCLIT[srcip] = IpNumCLIT[srcip] - 1
                    respuesta  = "LAN"
                else:
                    print "Paquete legitimo......"
                    respuesta  = "LAN"
					
	return respuesta

def payload(pkt,num1,num2):
	of_payload_code = pkt['raw']
	of_payload = of_payload_code.encode("hex")
	respuesta  = of_payload[num1:num2]

	
#Clase terminada  completamente... Revisar!!!!
