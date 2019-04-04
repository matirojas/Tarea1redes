import socket as libsock
import struct
import time

addr = "127.0.0.1"


def get_response():
    return "hola".encode()


def decode_labels(message, offset):
    labels = []

    while True:
        length, = struct.unpack_from("!B", message, offset)

        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", message, offset)
            offset += 2

            return labels + decode_labels(message, pointer & 0x3FFF), offset

        if (length & 0xC0) != 0x00:
            raise StandardError("unknown label encoding")

        offset += 1

        if length == 0:
            return labels, offset

        labels.append(*struct.unpack_from("!%ds" % length, message, offset))
        offset += length


DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")


def decode_question_section(message, offset, qdcount):
    questions = []

    for _ in range(qdcount):
        qname, offset = decode_labels(message, offset)

        qtype, qclass = DNS_QUERY_SECTION_FORMAT.unpack_from(message, offset)
        offset += DNS_QUERY_SECTION_FORMAT.size

        question = {"domain_name": qname,
                    "query_type": qtype,
                    "query_class": qclass}

        questions.append(question)

    return questions, offset


def decode_mati(message, offset):
    qname, offset = decode_labels(message, offset)
    qtype, qclass = DNS_QUERY_SECTION_FORMAT.unpack_from(message, offset)
    offset += DNS_QUERY_SECTION_FORMAT.size
    question = {"domain_name": qname,
                "query_type": qtype,
                "query_class": qclass}
    return question


DNS_QUERY_MESSAGE_HEADER = struct.Struct("!6H")


def decode_dns_message(message):
    id, misc, qdcount, ancount, nscount, arcount = DNS_QUERY_MESSAGE_HEADER.unpack_from(message)

    qr = (misc & 0x8000) != 0
    opcode = (misc & 0x7800) >> 11
    aa = (misc & 0x0400) != 0
    tc = (misc & 0x200) != 0
    rd = (misc & 0x100) != 0
    ra = (misc & 0x80) != 0
    z = (misc & 0x70) >> 4
    rcode = misc & 0xF

    offset = DNS_QUERY_MESSAGE_HEADER.size
    question = decode_mati(message, offset)

    result = {"id": id,
              "is_response": qr,
              "opcode": opcode,
              "is_authoritative": aa,
              "is_truncated": tc,
              "recursion_desired": rd,
              "recursion_available": ra,
              "reserved": z,
              "response_code": rcode,
              "question_count": qdcount,
              "answer_count": ancount,
              "authority_count": nscount,
              "additional_count": arcount,
              "questions": question}

    return result


def server(port):
    socket = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)  # SOCK_DGRAM es UDP
    socket2 = libsock.socket(libsock.AF_INET, libsock.SOCK_DGRAM)  # SOCK_DGRAM es UDP

    print("listening on {}:{}...".format(addr, port))
    socket.bind((addr, port))

    while True:
        data, address = socket.recvfrom(1024)
        queries = decode_dns_message(data)
        print("Pregunta: ", queries)
        type = queries['questions']['query_type']
        print(type)
        if (type == 28 or type == 1 or type == 15):
            fecha = time.strftime("%d/%m/%y") + " " + time.strftime("%H:%M:%S")
            texto = str(address[0]) + " " + fecha + "\n"
            logs = open("logs.txt", "a")
            logs.write(texto)
            logs.close()
            # socket.connect(("8.8.8.8", 53))
            socket2.sendto(data, ("8.8.8.8", 53))
            data2, addr2 = socket2.recvfrom(1024)
            print("Respuesta", decode_dns_message(data2))
            print(addr2)
            socket.sendto(get_response(), address)
        else:
            print("malo")


def main():
    port = input("Ingrese su puerto: ")
    server(int(port))


main()
