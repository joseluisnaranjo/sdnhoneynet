###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

from ConfigParser import ConfigParser
import enviar
def thc_ssl_dos(red, pkt, ListaAtacantes, ListaClientes, ListaSolicitudes):
    config = ConfigParser()
    config.read("honeynet.cfg")
    ipServidor = config.get("SYNFLOOD", "ipServidor")
    tamano_max_listasolicitudes = config.get("SYNFLOOD", "tamano")
    srcip  = pkt['srcip']

    ssl_flags = payload(pkt, 120, 122)
    print ssl_flags
    of_payload_code = pkt['raw']
    #A continucaion se codifica en hexadecimal dicho payload
    of_payload = of_payload_code.encode("hex")
    print of_payload
    ssl_datos = payload(pkt, 110, 112)
    print ssl_datos


    if str(ssl_flags) == "01":
            if srcip in ListaAtacantes:
                print "Enviar ala Honeynet..."
                enviar.enviar_Honeynet(pkt, red)

            else:
                if srcip in ListaSolicitudes:
                    ListaSolicitudes.remove(srcip)
                    ListaAtacantes.append(srcip)
                    print "Enviar ala Honeynet..."
                    enviar.enviar_Honeynet(pkt, red)
                else:
                    if srcip in ListaClientes:
                        print "Enviar a la LAN..."
                        enviar.enviar_paquete(pkt, red)
                    else:
                        if len(ListaSolicitudes) < tamano_max_listasolicitudes:
                            ListaSolicitudes.append(srcip)
                            print "Enviar a la LAN..."
                            enviar.enviar_paquete(pkt, red)
                        else:
                            ListaAtacantes.append(ListaSolicitudes[0])
                            del ListaSolicitudes[0]
                            ListaSolicitudes.append(srcip)
                            print "Enviar a la LAN..."
                            enviar.enviar_paquete(pkt, red)
    else:
            if str(ssl_datos) == "23":
                if srcip in ListaSolicitudes:
                    ListaSolicitudes.remove(srcip)
                    ListaClientes.append(srcip)
                    print "Enviar a la LAN..."
                    enviar.enviar_paquete(pkt, red)

                else:
                    if srcip in ListaAtacantes:
                         ListaAtacantes.remove(srcip)
                         ListaClientes.append(srcip)
                         print "Enviar a la LAN..."
                         enviar.enviar_paquete(pkt, red)

                    else:
                        print "Enviar a la LAN..."
                        enviar.enviar_paquete(pkt, red)
            else:
                print "Enviar a la LAN..."
                enviar.enviar_paquete(pkt, red)


def payload(pkt,num1,num2):
	of_payload_code = pkt['raw']
	#A continucaion se codifica en hexadecimal dicho payload
	of_payload = of_payload_code.encode("hex")
	#A continuacion se  extrae alguas bandetas de TCP, aquellas que nos indican si es syn, syn-ack y ack
	return of_payload[num1:num2]


