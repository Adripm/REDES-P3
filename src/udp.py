from ip import *
import struct

import logging

UDP_HLEN = 8
UDP_PROTO = 17

def getUDPSourcePort():
    '''
        Nombre: getUDPSourcePort
        Descripción: Esta función obtiene un puerto origen libre en la máquina actual.
        Argumentos:
            -Ninguno
        Retorno: Entero de 16 bits con el número de puerto origen disponible

    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(('', 0))
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    portNum = s.getsockname()[1]
    s.close()

    return portNum

def process_UDP_datagram(us, header, data, srcIP):
    '''
        Nombre: process_UDP_datagram
        Descripción: Esta función procesa un datagrama UDP. Esta función se ejecutará por cada datagrama IP que contenga
        un 17 en el campo protocolo de IP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Extraer los campos de la cabecera UDP
            -Loggear (usando logging.debug) los siguientes campos:
                -Puerto origen
                -Puerto destino
                -Datos contenidos en el datagrama UDP

        Argumentos:
            -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
            -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
            -data: array de bytes con el conenido del datagrama UDP
            -srcIP: dirección IP que ha enviado el datagrama actual.
        Retorno: Ninguno

    '''
    # Extraer campos
    source_port = struct.unpack('!H', data[0:2])[0] # 2 bytes
    dest_port = struct.unpack('!H', data[2:4])[0] # 2 bytes
    # length = struct.unpack('!H', data[4:6]) # 2 bytes
    # checksum = struct.unpack('!H', data[6:8]) # 2 bytes

    # En esta práctica, checksum siempre será 0. No hará falta comprobarlo

    logging.info('Source Port:'+str(source_port))
    logging.info('Destination Port:'+str(dest_port))
    logging.info('Payload:'+str(data.hex()))

def sendUDPDatagram(data, dstPort, dstIP):
    '''
        Nombre: sendUDPDatagram
        Descripción: Esta función construye un datagrama UDP y lo envía
        Esta función debe realizar, al menos, las siguientes tareas:
            -Construir la cabecera UDP:
                -El puerto origen lo obtendremos llamando a getUDPSourcePort
                -El valor de checksum lo pondremos siempre a 0
            -Añadir los datos
            -Enviar el datagrama resultante llamando a sendIPDatagram

        Argumentos:
            -data: array de bytes con los datos a incluir como payload en el datagrama UDP
            -dstPort: entero de 16 bits que indica el número de puerto destino a usar
            -dstIP: entero de 32 bits con la IP destino del datagrama UDP
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no
    '''
    # Crear trama UDP
    datagram = bytes()
    datagram += struct.pack('!H', getUDPSourcePort()) # Source Port - 2 Bytes
    datagram += struct.pack('!H', dstPort) # Destination Port - 2 Bytes
    datagram += struct.pack('!H', UDP_HLEN + len(data)) # Length - 2 Bytes
    datagram += bytes([0x00, 0x00]) # Checksum - 2 Bytes - Es opcional, en la práctica su valor siempre será cero
    datagram += data

    return sendIPDatagram(dstIP, datagram, UDP_PROTO)

def initUDP():
    '''
        Nombre: initUDP
        Descripción: Esta función inicializa el nivel UDP
        Esta función debe realizar, al menos, las siguientes tareas:
            -Registrar (llamando a registerIPProtocol) la función process_UDP_datagram con el valor de protocolo 17

        Argumentos:
            -Ninguno
        Retorno: Ninguno

    '''
    registerIPProtocol(process_UDP_datagram, UDP_PROTO)
