import socket as libsock
import struct
import time
from datetime import datetime
from datetime import timedelta
import csv
import ast


addr = "127.0.0.1"

def changeUrl(data, newUrl):
    DNSHeader = struct.Struct("!6h")

    offset1 = DNSHeader.size

    #DNSQuestion = struct.Struct("!2H")
    _, offset2 = getUrl(data, offset1)

    #print(data[0:offset1]) #header
    #print(data[offset1:offset2]) #cambiar
    #print(data[offset2:])#el resto

    urlBytes = packUrl(newUrl)

    result = data[0:offset1] + urlBytes + data[offset2:]

    print("Resultado", result)

    return result


def packUrl(url):
    arr = url.split(".")
    result= b''
    print(arr)
    for i in range(0,len(arr)):
        print(arr[i])
        s = bytes(arr[i], 'utf-8')
        result+= struct.pack("!B", len(s))
        result+= struct.pack("!%ds" % (len(s)), s)
    result+= struct.pack("!B", 0)
    return result


def getNoAnswer(domainName):
    print("getNoAnswer()")
    noAnswer = False
    with open('noAnswer.csv', 'r') as f:
        csv_reader = csv.reader(f)
        for line in csv_reader:
            print(line)
            print(line[0])
            print(domainName)
            if noAnswer:
                break
            if line[0]==domainName:
                noAnswer = True
        f.close()
    return noAnswer

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



def getIdHeader(data):
    DNSHeader = struct.Struct("!H")
    headerId = DNSHeader.unpack_from(data)
    return headerId

def changeHeader(question, response):
    headerQuestion = question[0:2]
    restResponse =  response[2:]
    return headerQuestion + restResponse

def logManager(address, answer):
    fecha = time.strftime("%d/%m/%y") + " " + time.strftime("%H:%M:%S")
    texto = address  + " " + fecha + " " + answer + "\n"
    logs = open("logs.txt", "a")
    logs.write(texto)
    logs.close()

def cacheFilter(domain, tipo):
    cacheResponse = None
    with open('cache.csv', 'r') as file:
        lista = list(csv.reader(file))
        for line in lista:
            print(line)
            if line[0] == domain and line[1] == str(tipo):
                queryDate = datetime.strptime(line[3], '%Y-%m-%d %H:%M:%S.%f')
                queryDateMax = queryDate + timedelta(hours=1)

                if queryDateMax > datetime.now():
                    #Mantener cache y usar respuesta
                    cacheResponse = line[2]
                else:
                    #Borrar cache
                    line[4] = 1
            #else:
            #    escribir = 1
    file.close()

    fa = open("cache.csv", "w")
    fa.truncate()
    fa.close()

    with open('cache.csv', 'a') as f:
        writer = csv.writer(f)
        print(lista)
        for line in lista:
            if line[4] == '0':
                writer.writerow(line)
    f.close()

    return cacheResponse

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

        if length == 0: #Se encuentra un byte= 0. Se termino qname
            url = url[:-1]
            return url, offset

        #Si llegamos aca, el length es el largo del label.
        #a = "!%ds" % length;

        element = struct.unpack_from("!%ds" % length, message, offset)
        url += element[0].decode('utf-8') + "."
        offset += length


def getQuestion(message, offset):
    #Cambiar nombre valores
    DNSQuestion = struct.Struct("!2H")
    qname, offset = getUrl(message, offset)
    qtype, qclass = DNSQuestion.unpack_from(message, offset)
    offset += DNSQuestion.size
    question = {"domain_name": qname,
                "type": qtype,
                "query_class": qclass}
    return question, offset

def getAnswer(message, offset, answerNumber, questionType):
    #Agregar question type, para que sea el mismo
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
        print("RDLENGTH ",rdlength[0])
        if type == 1 and questionType == type: #Caso A
            ip = struct.unpack_from("!%dB" % rdlength[0], message, offset)
            print("IP", ip)
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
            print("IP", ip)
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
            wea1 = struct.unpack_from("!2B", message, offset)
            offset += struct.Struct("!2B").size
            wea2, offset2 = getUrl(message, offset)
            offset = offset2
            wea3 = str(wea1[1]) + " " + wea2 + "."

            answers.append(wea3)

        else:
            DNSFinal = struct.Struct("!%dB" % rdlength[0])
            offset += DNSFinal.size
    return answers

def translate(data):
    #Cambiar el nombre de dnsheader
    #Cambiar nombre de misc, qdcount, etc.
    #Sacar solo 4 valores, y sumarle mas al offset
    answers = []

    DNSHeader = struct.Struct("!6h")
    id, misc, qdcount, ancount, _, _ = DNSHeader.unpack_from(data)
    qr = (misc & 0x8000) != 0
    rcode = misc & 0xF

    offset = DNSHeader.size

    question, offset = getQuestion(data, offset)

    message = {"is_response": qr,
              "response_code": rcode,
              "question_count": qdcount,
              "answer_count": ancount,
              "question": question}

    if(qr == True):
        answers = getAnswer(data, offset, ancount, question['type'])

    return message, answers

def server(port, resolver):
    socketClient = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)
    socketServer = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)
    print("Escuchando en {}:{}...".format(addr, port))
    socketClient.bind((addr, port))

    while True:
        questionRaw, address = socketClient.recvfrom(1024)
        question, _ = translate(questionRaw)
        print("Pregunta:", question)
        tipo = question['question']['type']
        domainName = question['question']['domain_name']
        noAnswer = getNoAnswer(domainName)

        redirect, redirectUrl = getRedirect(domainName)

        if (tipo == 28 or tipo == 1 or tipo == 15) and  redirect and not noAnswer:
            changedQuestion = changeUrl(questionRaw, redirectUrl)
            question, _ = translate(changedQuestion)
            tipo = question['question']['type']
            originalDomainName = domainName
            domainName = question['question']['domain_name']

            cacheResponse = cacheFilter(domainName, tipo)
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

            cacheResponse = cacheFilter(domainName, tipo)
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
            print("answers:", answers)
            logManager(address[0], answers[0])

        else:
            print("no response")
            socketClient.sendto(questionRaw, address)

def main():
    port = input("Ingrese su puerto: ")
    resolver = input("Ingrese el resolver: ")
    server(int(port), resolver)

main()