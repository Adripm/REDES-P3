from ethernet import *
from arp import *
from fcntl import ioctl
import subprocess
SIOCGIFMTU = 0x8921
SIOCGIFNETMASK = 0x891b

from math import ceil
import logging

#Diccionario de protocolos. Las claves con los valores numéricos de protocolos de nivel superior a IP
#por ejemplo (1, 6 o 17) y los valores son los nombres de las funciones de callback a ejecutar.
protocols={}
#Valor inicial para el IPID
IPID = 0
#Valor de ToS por defecto
DEFAULT_TOS = 0
#Tamaño mínimo de la cabecera IP
IP_MIN_HLEN = 20
#Tamaño máximo de la cabecera IP
IP_MAX_HLEN = 60
#Valor de TTL por defecto
DEFAULT_TTL = 64

def chksum(msg):
    '''
        Nombre: chksum
        Descripción: Esta función calcula el checksum IP sobre unos datos de entrada dados (msg)
        Argumentos:
            -msg: array de bytes con el contenido sobre el que se calculará el checksum
        Retorno: Entero de 16 bits con el resultado del checksum en ORDEN DE RED
    '''
    s = 0
    for i in range(0, len(msg), 2):
        if (i+1) < len(msg):
            a = msg[i]
            b = msg[i+1]
            s = s + (a+(b << 8))
        elif (i+1)==len(msg):
            s += msg[i]
        else:
            raise 'Error calculando el checksum'
    s = s + (s >> 16)
    s = ~s & 0xffff

    return s

def getMTU(interface):
    '''
        Nombre: getMTU
        Descripción: Esta función obteiene la MTU para un interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la MTU
        Retorno: Entero con el valor de la MTU para la interfaz especificada
    '''
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    ifr = struct.pack('16sH', interface.encode("utf-8"), 0)
    mtu = struct.unpack('16sH', ioctl(s,SIOCGIFMTU, ifr))[1]

    s.close()

    return mtu

def getNetmask(interface):
    '''
        Nombre: getNetmask
        Descripción: Esta función obteiene la máscara de red asignada a una interfaz
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar la máscara
        Retorno: Entero de 32 bits con el valor de la máscara de red
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = fcntl.ioctl(
        s.fileno(),
       SIOCGIFNETMASK,
        struct.pack('256s', (interface[:15].encode('utf-8')))
    )[20:24]
    s.close()
    return struct.unpack('!I',ip)[0]


def getDefaultGW(interface):
    '''
        Nombre: getDefaultGW
        Descripción: Esta función obteiene el gateway por defecto para una interfaz dada
        Argumentos:
            -interface: cadena con el nombre la interfaz sobre la que consultar el gateway
        Retorno: Entero de 32 bits con la IP del gateway
    '''
    p = subprocess.Popen(['ip r | grep default | awk \'{print $3}\''], stdout=subprocess.PIPE, shell=True)
    dfw = p.stdout.read().decode('utf-8')
    # print(dfw)
    return struct.unpack('!I',socket.inet_aton(dfw))[0]



def process_IP_datagram(us,header,data,srcMac):
    '''
        Nombre: process_IP_datagram
        Descripción: Esta función procesa datagramas IP recibidos.
            Se ejecuta una vez por cada trama Ethernet recibida con Ethertype 0x0800
            Esta función debe realizar, al menos, las siguientes tareas:
                -Extraer los campos de la cabecera IP (includa la longitud de la cabecera)
                -Calcular el checksum sobre los bytes de la cabecera IP
                    -Comprobar que el resultado del checksum es 0. Si es distinto el datagrama se deja de procesar
                -Analizar los bits de de MF y el offset. Si el offset tiene un valor != 0 dejar de procesar el datagrama (no vamos a reensamblar)
                -Loggear (usando logging.debug) el valor de los siguientes campos:
                    -Longitud de la cabecera IP
                    -IPID
                    -Valor de las banderas DF y MF
                    -Valor de offset
                    -IP origen y destino
                    -Protocolo
                -Comprobar si tenemos registrada una función de callback de nivel superior consultando el diccionario protocols y usando como
                clave el valor del campo protocolo del datagrama IP.
                    -En caso de que haya una función de nivel superior registrada, debe llamarse a dicha función
                    pasando los datos (payload) contenidos en el datagrama IP.

        Argumentos:
            -us: Datos de usuario pasados desde la llamada de pcap_loop. En nuestro caso será None
            -header: cabecera pcap_pktheader
            -data: array de bytes con el contenido del datagrama IP
            -srcMac: MAC origen de la trama Ethernet que se ha recibido
        Retorno: Ninguno
    '''
    # Comprobar checksum
    if chksum(data) != 0:
        # Error
        return

    # Comprobar MF y offset
    offset = struct.unpack('!H', (data[6:8] & 0x1FFF)) # 13 bits menos significativos
    if offset != 0:
        # No reensamblar
        return

    # Extraer campos
    ihl = data[0] & (0x0F) # 4 bits más a la derecha
    df = (data[6] & 0x20) >> 6 # segundo bit más significativo
    mf = (data[6] & 0x10) >> 5 # tercer bit más significativo
    id = struct.unpack('!H', data[4:6]) # 2 bytes
    ip_origen = struct.unpack('!I', data[12:16]) # 4 bytes
    ip_dest = struct.unpack('!I', data[16:20]) # 4 bytes
    prot = struct.unpack('!B', data[9]) # 1 Byte

    # Logging
    logging.debug('IHL:', ihl) # palabras de 4 bytes
    logging.debug('IPID:', id)
    logging.debug('DF:', df)
    logging.debug('MF:', mf)
    logging.debug('Offset:', offset)
    logging.debug('IP origen:',ip_origen)
    logging.debug('IP destino:',ip_dest)
    logging.debug('Protocol:',prot)

    payload = data[ihl*4:]

    if prot in protocols:
        protocols[prot](us, header, payload, ip_origen)

def registerIPProtocol(callback,protocol):
    '''
        Nombre: registerIPProtocol
        Descripción: Esta función recibirá el nombre de una función y su valor de protocolo IP asociado y añadirá en la tabla
            (diccionario) de protocolos de nivel superior dicha asociación.
            Este mecanismo nos permite saber a qué función de nivel superior debemos llamar al recibir un datagrama IP  con un
            determinado valor del campo protocolo (por ejemplo TCP o UDP).
            Por ejemplo, podemos registrar una función llamada process_UDP_datagram asociada al valor de protocolo 17 y otra
            llamada process_ICMP_message asocaida al valor de protocolo 1.
        Argumentos:
            -callback_fun: función de callback a ejecutar cuando se reciba el protocolo especificado.
                La función que se pase como argumento debe tener el siguiente prototipo: funcion(us,header,data,srcIp):
                Dónde:
                    -us: son los datos de usuarios pasados por pcap_loop (en nuestro caso este valor será siempre None)
                    -header: estructura pcap_pkthdr que contiene los campos len, caplen y ts.
                    -data: payload del datagrama IP. Es decir, la cabecera IP NUNCA se pasa hacia arriba.
                    -srcIP: dirección IP que ha enviado el datagrama actual.
                La función no retornará nada. Si un datagrama se quiere descartar basta con hacer un return sin valor y dejará de procesarse.
            -protocol: valor del campo protocolo de IP para el cuál se quiere registrar una función de callback.
        Retorno: Ninguno
    '''
    protocols[protocol] = callback

def initIP(interface,opts=None):
    global myIP, MTU, netmask, defaultGW, ipOpts
    '''
        Nombre: initIP
        Descripción: Esta función inicializará el nivel IP. Esta función debe realizar, al menos, las siguientes tareas:
            -Llamar a initARP para inicializar el nivel ARP
            -Obtener (llamando a las funciones correspondientes) y almacenar en variables globales los siguientes datos:
                -IP propia
                -MTU
                -Máscara de red (netmask)
                -Gateway por defecto
            -Almacenar el valor de opts en la variable global ipOpts
            -Registrar a nivel Ethernet (llamando a registerCallback) la función process_IP_datagram con el Ethertype 0x0800
        Argumentos:
            -interface: cadena de texto con el nombre de la interfaz sobre la que inicializar ip
            -opts: array de bytes con las opciones a nivel IP a incluir en los datagramas o None si no hay opciones a añadir
        Retorno: True o False en función de si se ha inicializado el nivel o no
    '''

    myIP = None
    MTU = None
    netmask = None
    defaultGW = None

    if initARP(interface) == -1:
        return False

    myIP = getIP(interface)
    MTU = getMTU(interface)
    netmask = getNetmask(interface)
    defaultGW = getDefaultGW(interface)

    ipOpts = opts

    # Control de errores
    if not myIP or not MTU or not netmask or not defaultGW:
        return False

    # Registrar callback en el nivel de enlace
    registerCallback(process_IP_datagram, 0x0800)

    return True

def sendIPDatagram(dstIP,data,protocol):
    global IPID, ipOpts
    '''
        Nombre: sendIPDatagram
        Descripción: Esta función construye un datagrama IP y lo envía. En caso de que los datos a enviar sean muy grandes la función
        debe generar y enviar el número de fragmentos IP que sean necesarios.
        Esta función debe realizar, al menos, las siguientes tareas:
            -Determinar si se debe fragmentar o no y calcular el número de fragmentos
            -Para cada datagrama o fragmento:
                -Construir la cabecera IP con los valores que corresponda. Incluir opciones en caso de que ipOpts sea distinto de None
                -Calcular el checksum sobre la cabecera y añadirlo a la cabecera en la posición correcta
                -Añadir los datos a la cabecera IP
                -En el caso de que sea un fragmento ajustar los valores de los campos MF y offset de manera adecuada
                -Enviar el datagrama o fragmento llamando a sendEthernetFrame. Para determinar la dirección MAC de destino
                al enviar los datagramas:
                    -Si la dirección IP destino está en mi subred:
                        -Realizar una petición ARP para obtener la MAC asociada a dstIP y usar dicha MAC
                    -Si la dirección IP destino NO está en mi subred:
                        -Realizar una petición ARP para obtener la MAC asociada al gateway por defecto y usar dicha MAC
            -Para cada datagrama (no fragmento):
                -Incrementar la variable IPID en 1.
        Argumentos:
            -dstIP: entero de 32 bits con la IP destino del datagrama
            -data: array de bytes con los datos a incluir como payload en el datagrama
            -protocol: valor numérico del campo IP protocolo que indica el protocolo de nivel superior de los datos
            contenidos en el payload. Por ejemplo 1, 6 o 17.
        Retorno: True o False en función de si se ha enviado el datagrama correctamente o no

    '''
    header = bytearray()

    # Options padding
    if ipOpts:
        len_opts = len(ipOpts)
        if len_opts % 4 != 0: # No es múltiplo de 4 bytes
            to_pad = (ceil(len_opts / 4) * 4) - len_opts
            ipOpts = ipOpts.ljust(to_pad)
            len_opts = len(ipOpts)

    # Version - 4 BITS
    # IHL - 4 BITS
    ihl = IP_MIN_HLEN
    if ipOpts:
        ihl += len_opts
    if ihl > IP_MAX_HLEN:
        return False
    ihl = int(ihl / 4) # Palabras de 4 bytes
    version_ihl = struct.pack('!B', ((1 << 2)|ihl)) # 1 << 2 = 0100 = 4 = version
    header += version_ihl

    # Type of Service - 1 Byte
    header += struct.pack('!B', DEFAULT_TOS)

    # Total Length - 2 Bytes
    # En caso de fragmentación, se recalculará para cada fragmento
    length = (ihl*4) + len(data)
    header += struct.pack('!H', length)

    # Identification - 2 Bytes
    header += struct.pack('!H', IPID)

    # Flags - 3 BITS
    # Offset - 13 BITS
    # ---
    # 16 BITS = 2 Bytes
    # Por defecto, se pondrá a 0x0000. Más tarde, si se realiza la fragmentación,
    # estos valores (Flag MF y Offset) se cambiará para cada cabecera
    header += bytes([0x00, 0x00])

    # Time to Live - 1 Byte
    header += struct.pack('!B', DEFAULT_TTL)

    # Protocol - 1 Byte
    header += struct.pack('!B', protocol)

    # Header Checksum - 2 Bytes
    # ---
    # Por defecto, pondremos el checksum a 0 y se actualizará después
    # Variará para cada fragmento
    header += bytes([0x00, 0x00])

    # IP Origen - 4 Bytes
    header += struct.pack('!I', myIP)

    # IP Destino - 4 Bytes
    header += struct.pack('!I', dstIP)

    # Options - min 0 Bytes < max 40 bytes
    if ipOpts:
        header += ipOpts

    # Header construido, a excepción de Total Length (en caso de fragmentación), MF, offset y checksum
    # print('IP Header: ', header.hex())

    # Determinar si se debe fragmentar
    word_length = 8
    fragments = 1
    maxpayload = MTU-(ihl*4)
    if length > MTU: # length = len(header) + len(data)
        if maxpayload % word_length != 0: # No múltiplo de 8
            maxpayload = int(maxpayload/word_length)*word_length

        fragments = ceil(len(data)/maxpayload)
        # print('Fragments: ',fragments)

    # Other
    mf_flag = 0
    if fragments > 1:
        mf_flag = 1

    # Por cada fragmento
    for f in range(fragments):
        # Calcular Total Length, MF, offset y checksum

        # Offset y MF Flag
        offset = int((f*maxpayload)/word_length)
        # Insertar MF Flag en la tercera posición de flags
        # Las otras dos flags son siempre 0 en esta práctica
        if f == fragments - 1:
            mf_flag = 0
        if mf_flag == 1:
            header[6:8] = struct.pack('!H', (offset|(1<<14))) # 14 posiciones = bit 14 = tercer flag
        else:
            header[6:8] = struct.pack('!H', offset) # All flags = 0

        # Fragment payload
        payload = data[offset*word_length:]
        if len(payload) > maxpayload:
            payload = payload[:maxpayload]

        # Total length
        length = (ihl*4) + len(payload)
        header[2:4] = struct.pack('!H', length) # 2 Bytes

        # Checksum
        header[10:12] = bytes([0x00, 0x00]) # borrar cálculo previo antes de recalcular el checksum por posibles errores
        header[10:12] = struct.pack('!H', chksum(header)) # 2 bytes

        # Cabecera totalmente construida para un fragmento dado

        # Encontrar dirección MAC
        mac = None
        if myIP&netmask == dstIP&netmask: # Misma subred
            mac = ARPResolution(dstIP)
        else: # Diferente red
            mac = ARPResolution(defaultGW)

        if mac is None: # No encontrada
            return False

        # Enviar fragmentos
        frag = header + payload
        # print('----- Fragmento',f,'-----:\n',frag.hex())
        if sendEthernetFrame(frag, len(frag), 0x0800, mac) == -1: # 0x0800 = IPv4 Ethertype
            return False

    IPID += 1

    return True # Datagrama enviado correctamente
