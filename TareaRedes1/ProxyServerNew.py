import socket as libsock
import struct
import time
from datetime import datetime
from datetime import timedelta
import csv

addr = "127.0.0.1"


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

def getAnswer(message, offset, answerNumber):
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
        if(type == 1): #Caso A
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

        elif (type == 28): #Caso AAAA
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
        elif(type == 15):#Caso MX
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
    _, misc, qdcount, ancount, _, _ = DNSHeader.unpack_from(data)
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
        answers = getAnswer(data, offset, ancount)

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
        type = question['question']['type']
        noAnswer = False  ## Si esta variable es true entonces no hay que mandar respuesta

        if (type == 28 or type == 1 or type == 15):

            socketServer.sendto(questionRaw, (resolver, 53))
            responseRaw, addressServer = socketServer.recvfrom(1024)
            response, answers = translate(responseRaw)

            escribir = 1
            data = [question['question']['domain_name'],answers[0], datetime.now(),0]

            ## Aqui revisamos si esta en la lista negra, en dicho caso no mandamos respuesta.

            with open('noAnswer.csv','r') as f:
                csv_reader = csv.reader(f)
                for line in csv_reader:
                    if line[0]==data[0]:
                        noAnswer = True
            f.close()

            if noAnswer:
                break

            with open('cache.csv', 'r') as file:
                lista = list(csv.reader(file))
                for line in lista:
                    if line[0]==question['question']['domain_name']:
                        thatFecha = datetime.strptime(line[2], '%Y-%m-%d %H:%M:%S.%f')
                        thatFecha2 = thatFecha + timedelta(hours=1)
                        if(thatFecha2 > datetime.now()):
                            print("mantener cache")
                            response = line[1]
                            escribir = 0
                        else:
                            print("borrar cache")
                            line[3]=1
                            print("linea a borrar",line)
                            #borrar cache
                            escribir = 1
                    else:
                        print("escribir nueva fila")
                        escribir = 1
            file.close()

            fa = open("cache.csv", "w")
            fa.truncate()
            fa.close()

            with open('cache.csv', 'a') as f:
                writer = csv.writer(f)
                print(lista)
                for line in lista:
                    if line[3] =='0':
                        writer.writerow(line)
            f.close()

            if escribir:
                print("estoy aquii")
                with open('cache.csv', 'a') as file:
                    csv_writer = csv.writer(file)
                    csv_writer.writerow(data)
            file.close()

            fecha = time.strftime("%d/%m/%y") + " " + time.strftime("%H:%M:%S")
            texto = str(address[0]) + " " + fecha + " " + answers[0] +"\n"
            logs = open("logs.txt", "a")
            logs.write(texto)
            logs.close()

            socketClient.sendto(responseRaw, address)
        else:
            socketClient.sendto(questionRaw, address)

def main():
    port = input("Ingrese su puerto: ")
    resolver = input("Ingrese el resolver: ")
    server(int(port), resolver)

main()