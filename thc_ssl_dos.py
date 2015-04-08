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
def thc_ssl_dos(red, pkt, ListaAtacantes, ListaClientes, ListaSolicitudes, IpNum):
    config = ConfigParser()
    config.read("honeynet.cfg")
    ipServidor = config.get("SYNFLOOD", "ipServidor")
    num_max_conexiones = config.getint("SYNFLOOD", "num")
    tamano_max_listasolicitudes = config.get("SYNFLOOD", "tamano")
    srcip  = pkt['srcip']
    ssl_flags = payload(pkt, 142, 144)
    ssl_datos = payload(pkt, 134, 136)

    if ipServidor == srcip:
        print "Enviar a la LAN..."
        enviar.enviar_paquete(pkt, red)

    else:
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
                            if IpNum.has_key(srcip):
                                if IpNum[srcip] < num_max_conexiones:
                                    IpNum[srcip] = IpNum[srcip] + 1
                                    print "Enviar a la LAN..."
                                    enviar.enviar_paquete(pkt, red)
                                else:
                                    ListaClientes.remove(srcip)
                                    ListaAtacantes.append(srcip)
                                    del IpNum[srcip]
                                    print "Enviar ala Honeynet..."
                                    enviar.enviar_Honeynet(pkt, red)
                            else:
                                IpNum[srcip] = 1
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
                if str(ssl_datos) == "17":
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
    of_payload = of_payload_code.encode("hex")
    print of_payload
    return of_payload[num1:num2]


