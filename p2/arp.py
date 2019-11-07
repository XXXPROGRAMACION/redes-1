'''
    arp.py
    Implementación del protocolo ARP y funciones auxiliares que permiten realizar resoluciones de direcciones IP.
    Autor: Javier Ramos <javier.ramos@uam.es>
    2019 EPS-UAM
'''

from ethernet import *
import logging
import socket
import struct
import fcntl
import time
from threading import Lock
from expiringdict import ExpiringDict

#Semáforo global 
globalLock = Lock()
#Dirección de difusión (Broadcast)
broadcastAddr = bytes([0xFF]*6)
#Cabecera ARP común a peticiones y respuestas. Específica para la combinación Ethernet/IP
ARPHeader = bytes([0x00,0x01,0x08,0x00,0x06,0x04])
#longitud (en bytes) de la cabecera común ARP
ARP_HLEN = 6
ARP_ETHERTYPE = bytes([0x08, 0x06])

#Variable que almacenará que dirección IP se está intentando resolver
requestedIP = None
#Variable que almacenará que dirección MAC resuelta o None si no se ha podido obtener
resolvedMAC = None
#Variable que almacenará True mientras estemos esperando una respuesta ARP
awaitingResponse = False

#Variable para proteger la caché
cacheLock = Lock()
#Caché de ARP. Es un diccionario similar al estándar de Python solo que eliminará las entradas a los 10 segundos
cache = ExpiringDict(max_len=100, max_age_seconds=10)



def getIP(interface):
    '''
        Nombre: getIP
        Descripción: Esta función obtiene la dirección IP asociada a una interfaz. Esta funció NO debe ser modificada
        Argumentos:
            -interface: nombre de la interfaz
        Retorno: Entero de 32 bits con la dirección IP de la interfaz
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def printCache():
    '''
        Nombre: printCache
        Descripción: Esta función imprime la caché ARP
        Argumentos: Ninguno
        Retorno: Ninguno
    '''
    print('{:>12}\t\t{:>12}'.format('IP','MAC'))
    with cacheLock:
        for k in cache:
            if k in cache:
                print ('{:>12}\t\t{:>12}'.format(socket.inet_ntoa(struct.pack('!I',k)),':'.join(['{:02X}'.format(b) for b in cache[k]])))


def processARPRequest(data, MAC):
    '''
        Nombre: processARPRequest
        Decripción: Esta función procesa una petición ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer la MAC origen contenida en la petición ARP
            -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
            -Extraer la IP origen contenida en la petición ARP
            -Extraer la IP destino contenida en la petición ARP
            -Comprobar si la IP destino de la petición ARP es la propia IP:
                -Si no es la propia IP retornar
                -Si es la propia IP:
                    -Construir una respuesta ARP llamando a createARPReply (descripción más adelante)
                    -Enviar la respuesta ARP usando el nivel Ethernet (sendEthernetFrame)
        Argumentos:
            -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
            -MAC: dirección MAC origen extraída por el nivel Ethernet
        Retorno: Ninguno
    '''
    global myMAC,myIP

    arp_sender_MAC = data[8:14]
    if arp_sender_MAC != MAC:
        return

    arp_target_ip = data[24:28]
    if arp_target_ip != myIP:
        return

    arp_sender_ip = data[14:18]

    arp_reply = createARPReply(arp_sender_ip, arp_sender_MAC)
    sendEthernetFrame(arp_reply, ARP_HLEN, ARP_ETHERTYPE, arp_sender_MAC)


def processARPReply(data, MAC):
    '''
        Nombre: processARPReply
        Decripción: Esta función procesa una respuesta ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer la MAC origen contenida en la petición ARP
            -Si la MAC origen de la trama ARP no es la misma que la recibida del nivel Ethernet retornar
            -Extraer la IP origen contenida en la petición ARP
            -Extraer la MAC destino contenida en la petición ARP
            -Extraer la IP destino contenida en la petición ARP
            -Comprobar si la IP destino de la petición ARP es la propia IP:
                -Si no es la propia IP retornar
                -Si es la propia IP:
                    -Comprobar si la IP origen se corresponde con la solicitada (requestedIP). Si no se corresponde retornar
                    -Copiar la MAC origen a la variable global resolvedMAC
                    -Añadir a la caché ARP la asociación MAC/IP.
                    -Cambiar el valor de la variable awaitingResponse a False
                    -Cambiar el valor de la variable requestedIP a None
        Las variables globales (requestedIP, awaitingResponse y resolvedMAC) son accedidas concurrentemente por la función ARPResolution y deben ser protegidas mediante un Lock.
        Argumentos:
            -data: bytearray con el contenido de la trama ARP (después de la cabecera común)
            -MAC: dirección MAC origen extraída por el nivel Ethernet
        Retorno: Ninguno
    '''
    global myMAC,myIP
    global requestedIP,resolvedMAC,awaitingResponse,cache

    arp_sender_MAC = data[8:14]
    if arp_sender_MAC != MAC:
        return

    arp_target_ip = data[24:28]
    if arp_target_ip != myIP.to_bytes(4, byteorder='big'):
        return

    arp_target_MAC = data[18:24]

    arp_sender_ip = data[14:18]
    if arp_sender_ip != requestedIP.to_bytes(4, byteorder='big'):
        return

    resolvedMAC = arp_sender_MAC

    cacheLock.acquire()
    cache[int.from_bytes(arp_sender_ip, byteorder='big', signed=False)] = arp_sender_MAC
    cacheLock.release()

    globalLock.acquire()
    awaitingResponse = False
    requestedIP = None
    globalLock.release()


def createARPRequest(ip):
    '''
        Nombre: createARPRequest
        Descripción: Esta función construye una petición ARP y devuelve la trama con el contenido.
        Argumentos: 
            -ip: dirección a resolver 
        Retorno: Bytes con el contenido de la trama de petición ARP
    '''
    global myMAC,myIP
    frame = bytearray()

    frame += ARPHeader
    frame += bytes([0x00, 0x01])
    frame += myMAC
    frame += myIP.to_bytes(4, byteorder='big')
    frame += bytes([0x00]*6)
    frame += ip.to_bytes(4, byteorder='big')
    
    return frame


def createARPReply(IP, MAC):
    '''
        Nombre: createARPReply
        Descripción: Esta función construye una respuesta ARP y devuelve la trama con el contenido.
        Argumentos: 
            -IP: dirección IP a la que contestar
            -MAC: dirección MAC a la que contestar
        Retorno: Bytes con el contenido de la trama de petición ARP
    '''
    global myMAC,myIP
    frame = bytearray()

    frame += ARPHeader
    frame += bytes([0x00, 0x02])
    frame += myMAC
    frame += myIP.to_bytes(4, byteorder='big')
    frame += MAC
    frame += IP.to_bytes(4, byteorder='big')
    #frame += bytes([0x00]*4)

    return frame


def process_arp_frame(us,header,data,srcMac):
    '''
        Nombre: process_arp_frame
        Descripción: Esta función procesa las tramas ARP. 
            Se ejecutará por cada trama Ethenet que se reciba con Ethertype 0x0806 (si ha sido registrada en initARP). 
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer la cabecera común de ARP (6 primeros bytes) y comprobar que es correcta
                -Extraer el campo opcode
                -Si opcode es 0x0001 (Request) llamar a processARPRequest (ver descripción más adelante)
                -Si opcode es 0x0002 (Reply) llamar a processARPReply (ver descripción más adelante)
                -Si es otro opcode retornar de la función
                -En caso de que no exista retornar
        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido de la trama ARP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''

    if header.len < 32:
        logging.debug('header.len ' + str(header.len) + ' no válida')

    if data[0:6] != ARPHeader:
        logging.debug('ARPHeader inválido')
        return

    opcode = data[6:8]

    if opcode == bytes([0x00, 0x01]):
        processARPRequest(data, srcMac)
    elif opcode == bytes([0x00, 0x02]):
        processARPReply(data, srcMac)
    else:
        logging.debug('opcode ' + str(opcode) + ' no válido')


def initARP(interface):
    '''
        Nombre: initARP
        Descripción: Esta función construirá inicializará el nivel ARP. Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar la función del callback process_arp_frame con el Ethertype 0x0806
            -Obtener y almacenar la dirección MAC e IP asociadas a la interfaz especificada
            -Realizar una petición ARP gratuita y comprobar si la IP propia ya está asignada. En caso positivo se debe devolver error.
            -Marcar la variable de nivel ARP inicializado a True
    '''
    global myIP, myMAC, arpInitialized

    registerCallback(process_arp_frame, ARP_ETHERTYPE)

    myIP = getIP(interface)
    myMAC = getHwAddr(interface)

    if ARPResolution(myIP) != None:
        return -1

    arpInitialized = True

    return 0


def ARPResolution(ip):
    '''
        Nombre: ARPResolution
        Descripción: Esta función intenta realizar una resolución ARP para una IP dada y devuelve la dirección MAC asociada a dicha IP 
            o None en caso de que no haya recibido respuesta. Esta función debe realizar, al menos, las siguientes tareas:
                -Comprobar si la IP solicitada existe en la caché:
                -Si está en caché devolver la información de la caché
                -Si no está en la caché:
                    -Construir una petición ARP llamando a la función createARPRequest (descripción más adelante)
                    -Enviar dicha petición
                    -Comprobar si se ha recibido respuesta o no:
                        -Si no se ha recibido respuesta reenviar la petición hasta un máximo de 3 veces. Si no se recibe respuesta devolver None
                        -Si se ha recibido respuesta devolver la dirección MAC
            Esta función necesitará comunicarse con el la función de recepción (para comprobar si hay respuesta y la respuesta en sí) mediante 3 variables globales:
                -awaitingResponse: indica si está True que se espera respuesta. Si está a False quiere decir que se ha recibido respuesta
                -requestedIP: contiene la IP por la que se está preguntando
                -resolvedMAC: contiene la dirección MAC resuelta (en caso de que awaitingResponse) sea False.
            Como estas variables globales se leen y escriben concurrentemente deben ser protegidas con un Lock
    '''
    global requestedIP,awaitingResponse,resolvedMAC

    MAC_cache = cache.get(ip)
    if MAC_cache != None:
        return MAC_cache

    request = createARPRequest(ip)

    globalLock.acquire()
    requestedIP = ip
    awaitingResponse = True
    globalLock.release()

    for i in range(0, 3):
        sendEthernetFrame(request, len(request), ARP_ETHERTYPE, broadcastAddr)
        for j in range(0, 10):
            time.sleep(.1)
            if not awaitingResponse:
                break
        if not awaitingResponse:
            break

    if awaitingResponse:
        return None

    return resolvedMAC
