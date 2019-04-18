import socket as libsock
import struct
import time
from datetime import datetime
from datetime import timedelta
import csv
import ast


addr = "127.0.0.1"

#Cambia el url de la consulta DNS RAW
def changeUrl(data, newUrl):
    DNSHeader = struct.Struct("!6h")

    offset1 = DNSHeader.size
    _, offset2 = getUrl(data, offset1)
    urlBytes = packUrl(newUrl)

    result = data[0:offset1] + urlBytes + data[offset2:]

    return result

#Convierte una url en bytes, con el formato para consultas DNS
def packUrl(url):
    arr = url.split(".")
    result= b''
    for i in range(0,len(arr)):
        s = bytes(arr[i], 'utf-8')
        result+= struct.pack("!B", len(s))
        result+= struct.pack("!%ds" % (len(s)), s)
    result+= struct.pack("!B", 0)
    return result

# Devuelve un boolean si el dominio tiene que ser respondido.
# Aqui, se lee el archivo 'noAnswer.csv' en cada fila se tiene el nombre de
# los dominios que no hay que responder
def getNoAnswer(domainName):
    noAnswer = False
    with open('noAnswer.csv', 'r') as f:
        csv_reader = csv.reader(f)
        for line in csv_reader:
            if noAnswer:
                break
            if line[0]==domainName:
                noAnswer = True
        f.close()
    return noAnswer

# Devuelve un boolean si el dominio hay que redirigirlo o no.
# Si es que hay que redirigirlo, devuelve también la url a redirigir.
# Se lee el archivo 'redirecciones.csv'. La primera columna es la
# url que hay que redirigir, y la segunda es la url a la cual uno se redirige.
def getRedirect(domainName):
    redirect = False
    redirectUrl = None
    with open('redirecciones.csv', 'r') as f:
        csv_reader = csv.reader(f)
        for line in csv_reader:
            if redirect:
                break
            elif line[0] == domainName:
                redirect = True
                redirectUrl = line[1]
        f.close()
    return redirect, redirectUrl

# Devuelve el id de la consulta DNS
def getIdHeader(data):
    DNSHeader = struct.Struct("!H")
    headerId = DNSHeader.unpack_from(data)
    return headerId

# Cambia el id del header del segundo argumento (response), con el del primero (question)
def changeHeader(question, response):
    headerQuestion = question[0:2]
    restResponse =  response[2:]
    return headerQuestion + restResponse

# Escribe en el archivo "logs.txt".
# Escribe los logs del servidor. La primera columna es el hostname, la segunda la fecha
# y la tercera la IP de respuesta
def logManager(address, answer):
    fecha = time.strftime("%d/%m/%y") + " " + time.strftime("%H:%M:%S")
    texto = address  + " " + fecha + " " + answer + "\n"
    logs = open("logs.txt", "a")
    logs.write(texto)
    logs.close()

# Busca en la cache un dominio con el tipo de consulta. En caso de no encontrar, retorna None.
# Si es que ya se ha realizado y no se ha terminado su tiempo de vida, se devuelve el valor
# asociado al cache. En caso que se termino su tiempo de vida, se borra del cache y se retorna
# None.
# El formato del cache son con las columnas:
# [0]"nombre de dominio" - [1]"tipo de consulta" - [2]"respuesta" - [3]"fecha de la consulta" - [4]"booleano eliminar"
def cacheFilter(domain, tipo, horas):
    cacheResponse = None
    with open('cache.csv', 'r') as file:
        lista = list(csv.reader(file))
        for line in lista:
            if line[0] == domain and line[1] == str(tipo):
                queryDate = datetime.strptime(line[3], '%Y-%m-%d %H:%M:%S.%f')
                queryDateMax = queryDate + timedelta(hours=horas)

                if queryDateMax > datetime.now():
                    #Mantener cache y usar respuesta
                    cacheResponse = line[2]
                else:
                    #Borrar cache
                    line[4] = 1
    file.close()

    fa = open("cache.csv", "w")
    fa.truncate()
    fa.close()

    with open('cache.csv', 'a') as f:
        writer = csv.writer(f)
        for line in lista:
            if line[4] == '0':
                writer.writerow(line)
    f.close()

    return cacheResponse

# Escribe un valor "data" en el cache.
def cacheWrite(data):
    with open('cache.csv', 'a') as file:
            csv_writer = csv.writer(file)
            csv_writer.writerow(data)
    file.close()

def getUrl(message, offset):
    url = ""
    while True:
        length, = struct.unpack_from("!B", message, offset)

        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", message, offset)
            offset += 2
            return url + getUrl(message,pointer & 0x3FFF)[0], offset

        offset += 1

        if length == 0: #Se encuentra un byte= 0. Se termino el nombre del dominio
            url = url[:-1]
            return url, offset

        element = struct.unpack_from("!%ds" % length, message, offset)
        url += element[0].decode('utf-8') + "."
        offset += length

# Obtiene una pregunta y el offset de la consulta DNS Raw
def getQuestion(message, offset):
    DNSQuestion = struct.Struct("!2H")
    domainName, offset = getUrl(message, offset)
    tipo, _ = DNSQuestion.unpack_from(message, offset)
    offset += DNSQuestion.size
    question = {"domain_name": domainName,
                "type": tipo,
                }
    return question, offset

# Obtiene las respuestas de una consulta DNS Raw
def getAnswer(message, offset, answerNumber, questionType):
    answers = []
    for _ in range(answerNumber):
        offset+=2
        type, rclass = struct.unpack_from("!2H", message, offset)

        DNS1 = struct.Struct("!2H")
        offset+=DNS1.size

        TTL = struct.unpack_from("!I", message, offset)

        DNS2 = struct.Struct("!I")

        offset+=DNS2.size

        rdlength = struct.unpack_from("!H", message, offset)

        DNS3 = struct.Struct("!H")
        offset += DNS3.size
        if type == 1 and questionType == type: #Caso A
            ip = struct.unpack_from("!%dB" % rdlength[0], message, offset)
            a = ""
            for i in range(len(ip)):
                if(i == len(ip)-1):
                    a += str(ip[i])
                else:
                    a += str(ip[i]) + "."
            offset += struct.Struct("!%dB" % rdlength[0]).size
            answers.append(a)

        elif type == 28 and questionType == type: #Caso AAAA
            ip = struct.unpack_from("!4H", message, offset)
            a = ""
            for i in range(len(ip)):
                if (i == len(ip) - 1):
                    a += format(ip[i],'x') + "::"
                else:
                    a += format(ip[i], 'x') + ":"
            DNS4 = struct.Struct("!8B")
            offset += DNS4.size
            ip2 = struct.unpack_from("!4H", message, offset)
            for i in range(len(ip2)):
                if (i == len(ip2) - 1):
                    a += format(ip2[i], 'x')
                else:
                    a += format(ip2[i], 'x') + ":"
            offset += struct.Struct("!4H").size
            answers.append(a)
        elif type == 15 and questionType == type:#Caso MX
            a = struct.unpack_from("!2B", message, offset)
            offset += struct.Struct("!2B").size
            b, offset2 = getUrl(message, offset)
            offset = offset2
            c = str(a[1]) + " " + b + "."
            answers.append(c)

        else:
            DNSFinal = struct.Struct("!%dB" % rdlength[0])
            offset += DNSFinal.size
    return answers

# Retorna la pregunta y las respuestas (si es que tiene) de una consulta DNS.
def translate(data):
    answers = []

    DNSHeader = struct.Struct("!6h")
    _, x, _, answerNumber, _, _ = DNSHeader.unpack_from(data)
    answerQuery = (x & 0x8000) != 0

    offset = DNSHeader.size

    question, offset = getQuestion(data, offset)


    if answerQuery:
        answers = getAnswer(data, offset, answerNumber, question['type'])

    return question, answers

# Funcion principal del servidor. El primer argumento es el puerto, el segundo el resolver utilizado y
# el ultimo, la cantidad de horas de vida del cache.
def server(port, resolver, horas):
    socketClient = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)
    socketServer = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)
    print("Escuchando en {}:{}...".format(addr, port))
    socketClient.bind((addr, port))

    while True:
        questionRaw, address = socketClient.recvfrom(1024)
        question, _ = translate(questionRaw)
        tipo = question['type']
        domainName = question['domain_name']
        noAnswer = getNoAnswer(domainName)

        redirect, redirectUrl = getRedirect(domainName)

        if (tipo == 28 or tipo == 1 or tipo == 15) and  redirect and not noAnswer:
            changedQuestion = changeUrl(questionRaw, redirectUrl)
            question, _ = translate(changedQuestion)
            tipo = question['type']
            originalDomainName = domainName
            domainName = question['domain_name']

            cacheResponse = cacheFilter(domainName, tipo, horas)
            resolverResponse = None

            if cacheResponse is None:
                print("No Cache")
                socketServer.sendto(changedQuestion, (resolver, 53))
                responseRaw, addressServer = socketServer.recvfrom(1024)
                data = [domainName, tipo, responseRaw, datetime.now(), 0]
                cacheWrite(data)
                resolverResponse = responseRaw
            else:
                print("Cache")
                resolverResponse = changeHeader(questionRaw, ast.literal_eval(cacheResponse))

            resolverResponse = changeUrl(resolverResponse, originalDomainName)
            socketClient.sendto(resolverResponse, address)
            _, answers = translate(resolverResponse)
            logManager(address[0], answers[0])


        elif (tipo == 28 or tipo == 1 or tipo == 15) and not noAnswer:

            cacheResponse = cacheFilter(domainName, tipo, horas)
            resolverResponse = None

            if cacheResponse is None:
                print("No Cache")
                socketServer.sendto(questionRaw, (resolver, 53))
                responseRaw, addressServer = socketServer.recvfrom(1024)
                data = [domainName, tipo, responseRaw, datetime.now(),0]
                cacheWrite(data)
                resolverResponse = responseRaw
            else:
                print("Cache")
                resolverResponse = changeHeader(questionRaw, ast.literal_eval(cacheResponse))

            socketClient.sendto(resolverResponse, address)
            _, answers = translate(resolverResponse)
            logManager(address[0], answers[0])

        else:
            print("no response")
            socketClient.sendto(questionRaw, address)

# Funcion principal
def main():
    port = input("Ingrese su puerto: ")
    resolver = input("Ingrese el resolver: ")
    horas = input("Tiempo de vida del cache en horas: ")
    server(int(port), resolver, int(horas))

main()