###################################################################################
#                        ESCUELA POLITECNICA NACIONAL                             #
# ------------------------------------------------------------------------------  #
# Tema: Aplicacion para el controlador pyretic                                    #
# Programador: Naranjo Villota Jose Luis  (joseluisnaranjo@hotmail.es)            #
#              Manzano Barrionuevo Andres Michael (andres_manzano017@hotmail.com) #
# Fecha: Lunes  20 de  Octubre de 2014                                            #
###################################################################################

from pyretic.lib.corelib import *
from ConfigParser import ConfigParser
import enviar

def thc_ssl_dos(red, pkt, ListaAtacantes, ListaClientes, ListaSolicitudes, IpNumC, IpNumS):

    config = ConfigParser()
    config.read("honeynet.cfg")
    ipServidor = config.get("SYNFLOOD", "ipServidor")
    num_max_conexiones = config.getint("SYNFLOOD", "num")
    tamano_max_listasolicitudes = config.getint("SYNFLOOD", "tamano")
    srcip  = pkt['srcip']
    dstip  = pkt['dstip']

    ssl_flags1= payload(pkt, 118, 120)
    ssl_flags2 = payload(pkt, 142, 144)
    ssl_dato1 = payload(pkt, 108, 110)
    ssl_dato2 = payload(pkt, 132, 134)

    if (str(ssl_flags1) == "01") or (str(ssl_flags2) == "01"):
        if srcip == IPAddr(ipServidor):
            enviar.enviar_paquete(pkt, red)
        else:
                if srcip in ListaAtacantes:
                    print "Enviar ala Honeynet..."
                    enviar.enviar_Honeynet(pkt, red)

                else:
                    if srcip in ListaSolicitudes:
                        if IpNumS.has_key(srcip):
                                if IpNumS[srcip] < num_max_conexiones:
                                    IpNumS[srcip] = IpNumS[srcip] + 1
                                    print "Enviar a la LAN..."
                                    enviar.enviar_paquete(pkt, red)
                                else:
                                    ListaSolicitudes.remove(srcip)
                                    ListaAtacantes.append(srcip)
                                    del IpNumS[srcip]
                                    print "Enviar ala Honeynet..."
                                    enviar.enviar_Honeynet(pkt, red)
                        else:
                            IpNumS[srcip] = 1
                            print "Enviar a la LAN..."
                            enviar.enviar_paquete(pkt, red)

                    else:
                        if srcip in ListaClientes:
                            if IpNumC.has_key(srcip):
                                if IpNumC[srcip] < num_max_conexiones:
                                    IpNumC[srcip] = IpNumC[srcip] + 1
                                    print "Enviar a la LAN..."
                                    enviar.enviar_paquete(pkt, red)
                                else:
                                    ListaClientes.remove(srcip)
                                    ListaAtacantes.append(srcip)
                                    del IpNumC[srcip]
                                    print "Enviar ala Honeynet..."
                                    enviar.enviar_Honeynet(pkt, red)
                            else:
                                IpNumC[srcip] = 1
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
                if (str(ssl_dato1) == "17") or (str(ssl_dato2) == "17"):
                    if dstip in ListaSolicitudes:
                        ListaSolicitudes.remove(dstip)
                        ListaClientes.append(dstip)
                        IpNumS[dstip] = IpNumS[dstip] - 1
                        print "Enviar a la LAN..."
                        enviar.enviar_paquete(pkt, red)

                    else:
                        if dstip in ListaAtacantes:
                             ListaAtacantes.remove(dstip)
                             ListaClientes.append(dstip)
                             print "Enviar a la LAN..."
                             enviar.enviar_paquete(pkt, red)

                        else:
                            if dstip in ListaClientes:
                                print "Enviar a la LAN..."
                                enviar.enviar_paquete(pkt, red)
                            else:
                                if srcip in ListaAtacantes:
                                    enviar.enviar_Honeynet(pkt, red)
                                else:
                                    enviar.enviar_paquete(pkt, red)

                else:
                    if srcip in ListaAtacantes:
                        enviar.enviar_Honeynet(pkt,red)
                    else:
                        print "Enviar a la LAN..."
                        enviar.enviar_paquete(pkt, red)


def payload(pkt,num1,num2):
    of_payload_code = pkt['raw']
    of_payload = of_payload_code.encode("hex")
    return of_payload[num1:num2]


