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

def thc_ssl_dos( pkt, lstAtacantes, dicSolicitudes, dicClientes ,ipServidor, num_max_conexiones):

    srcip  = pkt['srcip']
    ssl_flags1= payload(pkt, 118, 120)
    ssl_flags2 = payload(pkt, 142, 144)
    ssl_dato1 = payload(pkt, 108, 110)
    ssl_dato2 = payload(pkt, 132, 134)



    if ipServidor == srcip:
        print "Paquete legitimo"
        respuesta = "LAN"
    else:
        if (str(ssl_flags1) == "01") or (str(ssl_flags2) == "01"):
            if srcip in lstAtacantes:
                print "Paquete peligroso..."
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
                        print "Paquete legitimo......"
                        respuesta  = "LAN"

        else:

            if (str(ssl_dato1) == "17") or (str(ssl_dato2) == "17"):
                if dicSolicitudes.has_key(srcip):
                    del dicSolicitudes[srcip]
                    dicClientes[srcip] = 1
                    print "Paquete legitimo......"
                    respuesta  = "LAN"
                else:
                    if srcip in lstAtacantes:
                         lstAtacantes.remove(srcip)
                         dicClientes[srcip] = 1
                         print "Paquete legitimo......"
                         respuesta  = "LAN"
                    else:
                        if dicClientes.has_key(srcip):
                            try:
                                dicClientes[srcip] = dicClientes[srcip] - 1
                                print "Paquete legitimo......"
                                respuesta  = "LAN"

                            except:
                                print "El diccionario de clientes esta en 0"
                                respuesta ="LAN"
            else:
                print "Paquete desconocido......"
                respuesta  = "LAN"

	return respuesta



def payload(pkt,num1,num2):
    of_payload_code = pkt['raw']
    of_payload = of_payload_code.encode("hex")
    return of_payload[num1:num2]


