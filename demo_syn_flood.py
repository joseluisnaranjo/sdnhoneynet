###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

from ConfigParser import ConfigParser

def tcp_syn_flood(pkt, ListaAtacantes, ListaClientes, ListaSolicitudes):
    config = ConfigParser()
    config.read("honeynet.cfg")
    ipServidor = config.get("SYNFLOOD", "ipServidor")
    tamano_max_listasolicitudes = config.get("SYNFLOOD", "tamano")
    srcip  = pkt['srcip']
    tcp_flags = payload(pkt, 94, 96)

    if ipServidor == srcip:
        print "Enviar al proceso 2..."
        return "THC"
    else:
        if str(tcp_flags) == "02":
            if srcip in ListaAtacantes:
                print "Enviar ala Honeynet..."
                return "HONEYNEY"

            else:
                if srcip in ListaSolicitudes:
                    ListaSolicitudes.remove(srcip)
                    ListaAtacantes.append(srcip)
                    print "Enviar ala Honeynet..."
                    return "HONEYNEY"
                else:
                    if srcip in ListaClientes:
                        print "Enviar al proceso 2..."
                        return "THC"
                    else:
                        if len(ListaSolicitudes) < tamano_max_listasolicitudes:
                            ListaSolicitudes.append(srcip)
                            print "Enviar al proceso 2..."
                            return "THC"
                        else:
                            ListaAtacantes.append(ListaSolicitudes[0])
                            del ListaSolicitudes[0]
                            ListaSolicitudes.append(srcip)
                            print "Enviar al proceso 2 ..."
                            return "THC"
        else:
            print str(tcp_flags)
            if str(tcp_flags) == "10":
                if srcip in ListaSolicitudes:
                    ListaSolicitudes.remove(srcip)
                    ListaClientes.append(srcip)
                    print "Enviar al proceso 2..."
                    return "THC"
                else:
                    if srcip in ListaAtacantes:
                         ListaAtacantes.remove(srcip)
                         ListaClientes.append(srcip)
                         print "Enviar al proceso 2..."
                         return "THC"
                    else:
                        print "Enviar al proceso 2..."
                        return "THC"
            else:
                print "Enviar al proceso 2..."
                return "THC"

		
def payload(pkt,num1,num2):	
	of_payload_code = pkt['raw']
	#A continucaion se codifica en hexadecimal dicho payload
	of_payload = of_payload_code.encode("hex")
	#A continuacion se  extrae alguas bandetas de TCP, aquellas que nos indican si es syn, syn-ack y ack  
	return of_payload[num1:num2]				
		
