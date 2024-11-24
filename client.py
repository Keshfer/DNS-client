import socket
import random
from io import BytesIO
import struct
import time
#DNS Header
class Header:
    def __init__(self, id: int, flags: int, QDCOUNT = 0, ANCOUNT = 0, NSCOUNT = 0, ARCOUNT = 0):
        
        self.id = id
        self.flags = flags
        self.QDCOUNT = QDCOUNT
        self.ANCOUNT = ANCOUNT
        self.NSCOUNT = NSCOUNT
        self.ARCOUNT = ARCOUNT

    def __str__(self):
        return f"Header(id: {self.id}, flags: {self.flags}, Question count: {self.QDCOUNT}, Answer count: {self.ANCOUNT}, Authorities count: {self.NSCOUNT}, Additional count: {self.ARCOUNT})"
    def str(self):
        return self.__str__(self)
#DNS Question
class Question:
    def __init__(self, QNAME: bytes, QTYPE: int, QCLASS: int ):
        
        self.QNAME = QNAME     
        self.QTYPE = QTYPE
        self.QCLASS = QCLASS
    def __str__(self):
        return f"Question(QNAME: {self.QNAME}, QTYPE: {self.QTYPE}, QCLASS: {self.QCLASS})"
    def str(self):
        return self.__str__()

#Resource Record
class Resource_Record:
    def __init__(self, name: bytes, type: int, class_data: int, TTL: int, RDlen: int, Rdata: bytes ):
        self.name = name
        self.type = type
        self.class_data = class_data
        self.TTL = TTL
        self.RDlen = RDlen
        self.Rdata = Rdata
    
    def __str__(self):
        return f"ResourceRecord(name: {self.name}, type: {self.type} class_data: {self.class_data}, TTL: {self.TTL}, RDlen: {self.RDlen}, Rdata: {self.Rdata})"
    def str(self):
        return self.__str__()
class DNSPacket:
    def __init__(self, header: Header, questions: list[Question], answers: list[Resource_Record], authorities: list[Resource_Record], additionals: list[Resource_Record]):
        self.header = header
        self.questions = questions
        self.answers = answers
        self.authorities = authorities
        self.additionals = additionals
    def __str__(self):
        questions_str = []
        answers_str = []
        authorities_str = []
        additionals_str = []
        for x in self.questions:
            questions_str.append(x.str())
        for x in self.answers:
            answers_str.append(x.str())
        for x in self.authorities:
            authorities_str.append(x.str())
        for x in self.additionals:
            additionals_str.append(x.str())

        return f"DNSPacket(header: {self.header},\n questions: {"\n".join(questions_str)},\n answers: {"\n".join(answers_str)},\n authorities: {"\n".join(authorities_str)},\n additionals: {"\n".join(additionals_str)})"
    def str(self):
        return self.__str__()
#convert DNS Header to byte form
def header_to_bytes(header: Header):
    id = header.id
    flags = header.flags
    QDCOUNT = header.QDCOUNT
    ANCOUNT = header.ANCOUNT
    NSCOUNT = header.NSCOUNT
    ARCOUNT = header.ARCOUNT

    id_bytes = id.to_bytes(2, byteorder='big')
    flags_bytes = flags.to_bytes(2, byteorder='big')
    QDCOUNT_bytes = QDCOUNT.to_bytes(2, byteorder='big')
    ANCOUNT_bytes = ANCOUNT.to_bytes(2, byteorder='big')
    NSCOUNT_bytes = NSCOUNT.to_bytes(2, byteorder='big')
    ARCOUNT_bytes = ARCOUNT.to_bytes(2, byteorder='big')

    return id_bytes + flags_bytes + QDCOUNT_bytes + ANCOUNT_bytes + NSCOUNT_bytes + ARCOUNT_bytes

#convert DNS Question to bytes
def question_to_bytes(question: Question):
    QTYPE_bytes = question.QTYPE.to_bytes(2, byteorder='big')
    QCLASS_bytes = question.QCLASS.to_bytes(2, byteorder='big')
    return question.QNAME + QTYPE_bytes + QCLASS_bytes

#Convert domain name to bytes in format specified by RFC 1035 4.1.2
def encode_dns_name(name: str):
    #length of name in bytes + name in bytes + terminator: \x00
    chunk_list = name.split('.')
    encoded = b""
    for chunk in chunk_list:
        encoded += len(chunk).to_bytes()+ chunk.encode("ascii")
    return encoded + b"\x00"

def create_query(domain_name: str, record_type: int):
    name = encode_dns_name(domain_name)
    id = random.randint(0, 65535)
    flags = 0 #0 0000 0 0 0 0 000 0000
    header = Header(id = id, flags = flags, QDCOUNT = 1)
    question = Question(QNAME = name, QTYPE = record_type, QCLASS = 1 )
    query = header_to_bytes(header) + question_to_bytes(question)
    return query
def send_query(client_socket,query, destination):
    client_socket.sendto(query, destination)
    response, res_addr = client_socket.recvfrom(1024)
    return response

def parse_header(buffer):
    header_shorts = struct.unpack('!HHHHHH', buffer.read(12)) # 12 bytes
    return Header(header_shorts[0], header_shorts[1], header_shorts[2], header_shorts[3], header_shorts[4], header_shorts[5])

def decode_domain_name(buffer):
    chunks = []
    try:
        while (length := buffer.read(1)[0]) != 0: #checks to see if there are still domain name chunks to read. [0] is the byte that indicates how many character bytes there are
            if length & 0b11000000: #performs bitwise AND to check if there is compression.
                #length is compressed so decode it
                decoded_name = decode_compressed_domain_name(length, buffer)
                if decoded_name != None:
                    chunks.append(decoded_name)
                else:
                    return None
                break # break because decode_compressed_domain_name will handle 
            else:
                chunk = buffer.read(length)
                chunks.append(chunk) # read up to the specify length and store that name chunk in chunks
    except IndexError:
        print("unable to parse due to index out of range error")
        return None
    #buffer.read will eventually reach the terminator byte and end the loop
    return b".".join(chunks)

def decode_compressed_domain_name(length, buffer):
    pointer_bytes = bytes([length & 0b00111111]) + buffer.read(1) #OFFSET is 14 bytes total which is why we do (6 + 8)
    pointer = struct.unpack("!H", pointer_bytes)[0] #[0] because struct.unpack returns a tuple "The result is a tuple even if it contains exactly one item."
    current_pos = buffer.tell()
    buffer.seek(pointer)
    decoded_name = decode_domain_name(buffer) #will perform the normal parsing (the else body of the function) of the domain name
    #print(decoded_name)
    buffer.seek(current_pos)
    if decoded_name != None:
        return decoded_name
    else:
        return None

def parse_question(buffer):
    name = decode_domain_name(buffer)
    Qtype = buffer.read(2)
    Qtype = struct.unpack("!H", Qtype)
    Qclass = buffer.read(2)
    Qclass = struct.unpack("!H", Qclass)
    return Question(name, Qtype, Qclass)

def parse_record(buffer):
    name = decode_domain_name(buffer)
    data = buffer.read(10) # 10 because that's how many bytes the rest of the resource record takes up, excluding the RData
    type_, class_, TTL, RDlength = struct.unpack("!HHIH", data)
    record_data = buffer.read(RDlength)
    return Resource_Record(name = name, type = type_, class_data = class_, TTL= TTL, RDlen = RDlength, Rdata = record_data)

def parse_packet(response):
    buffer = BytesIO(response)
    header = parse_header(buffer)
    questions = []
    answers =[]
    authorities = []
    additionals = []
    for i in range(header.QDCOUNT):
        questions.append(parse_question(buffer))
    for i in range(header.ANCOUNT):
        answers.append(parse_record(buffer))
    for i in range(header.NSCOUNT):
        authorities.append(parse_record(buffer))
    for i in range(header.ARCOUNT):
        additionals.append(parse_record(buffer))
    return DNSPacket(header=header, questions=questions, answers=answers, authorities=authorities, additionals=additionals)

def ip4_string(ip_bytes):
    num_list =[]
    for i in ip_bytes:
        num_list.append(str(i))
    return ".".join(num_list)

def ip6_string(ip_bytes):
    hex = ip_bytes.hex()
    parts = [hex[i:i+4] for i in range(0, len(hex), 4)]
    return ":".join(parts)


root_servers = ['198.41.0.4', '170.247.170.2', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53']
query = create_query("tmz.com", 1) # 1 represents the resource record of type A: host address
#print(query)

#create socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.settimeout(10)
packet_received = False
#seek TLDs from root servers
start_time = time.time()
for ip in root_servers:
    for i in range(3):
        try:
            client_socket.sendto(query, (ip, 53))
            response, res_addr = client_socket.recvfrom(1024)
            resolver_RTT = time.time() - start_time
            print("received")
            packet = parse_packet(response)
            packet_received = True
            break
        except TimeoutError:
            print("time out occurred")
            if(i == 2):
                print("moving onto next root server IP")
    if packet_received:
        print("********** ROOT RESPONSE **********")
        header = packet.header
        questions = packet.questions
        answers = packet.answers
        authorities = packet.authorities
        additionals = packet.additionals
        TLD_list = []
        print("HEADER")
        print(header)
        print("QUESTIONS")
        for i in questions:
            print(i)
        print("ANSWERS")
        for i in answers:
            print(i)
        print("AUTHORITIES")
        for i in authorities:
            print(i)
            if(i.type ==2 and i.RDlen > 4): # auth.RDlen > 4 to filter out ip addresses labelled with type 2. Also very unlikely a domain name is two letters (1 length byte + 2 char bytes + 1 terminator byte)
                temp = BytesIO(i.Rdata)
                #print(bin(int.from_bytes(i.Rdata, byteorder="big")))
                decoded_Rdata = decode_domain_name(temp)
                if decoded_Rdata != None:
                    print(decoded_Rdata)
            else:
                ip4 = ip4_string(i.Rdata)
                print(ip4)
                TLD_list.append(ip4)
        print("ADDITIONALS")
        for i in additionals:
            print(i)
            if (i.RDlen == 4): # filtering for ipv4 addresses
                ip4 = ip4_string(i.Rdata)
                print(ip4)
                TLD_list.append(ip4)
            else: # ipv6 addresses
                print(ip6_string(i.Rdata))

        unique_TLD = list(set(TLD_list)) # filter out duplicate IPs
        print(unique_TLD)
        break
    
#seek Authority server IPs with TLDS 
packet_received = False
for ip in unique_TLD:
    for i in range(3):
        try:
            client_socket.sendto(query, (ip, 53))
            response, res_addr = client_socket.recvfrom(1024)
            print("received")
            packet = parse_packet(response)
            packet_received = True
            break
        except TimeoutError:
            print("time out occurred")
            if(i == 2):
                print("moving onto next TLD server IP")
    if packet_received:
        print("********** TLD RESPONSE **********")
        header = packet.header
        questions = packet.questions
        answers = packet.answers
        authorities = packet.authorities
        additionals = packet.additionals
        authorities_list = []
        print("HEADER")
        print(header)
        print("QUESTIONS")
        for i in questions:
            print(i)
        print("ANSWERS")
        for i in answers:
            print(i)
            ip4 = ip4_string(i.Rdata)
            print(ip4)
        print("AUTHORITIES")
        for i in authorities:
            print(i)
            if(i.type ==2 and i.RDlen > 4): # auth.RDlen > 4 to filter out ip addresses labelled with type 2. Also very unlikely a domain name is two letters (1 length byte + 2 char bytes + 1 terminator byte)
                temp = BytesIO(i.Rdata)
                #print(bin(int.from_bytes(i.Rdata, byteorder="big")))
                decoded_Rdata = decode_domain_name(temp)
                if decoded_Rdata != None:
                    print(decoded_Rdata)
            else:
                ip4 = ip4_string(i.Rdata)
                print(ip4)
                authorities_list.append(ip4)
        print("ADDITIONALS")
        for i in additionals:
            print(i)
            if (i.RDlen == 4): # filtering for ipv4 addresses
                ip4 = ip4_string(i.Rdata)
                print(ip4)
                authorities_list.append(ip4)
            else: # ipv6 addresses
                print(ip6_string(i.Rdata))

        unique_authorities = list(set(authorities_list)) # filter out duplicate IPs
        print(unique_authorities)
        break
#seek host address IPs with Authority servers
packet_received = False
for ip in unique_authorities:
    for i in range(3):
        try:
            client_socket.sendto(query, (ip, 53))
            response, res_addr = client_socket.recvfrom(1024)
            print("received")
            packet = parse_packet(response)
            packet_received = True
            break
        except:
            print("time out occurred")
            if(i == 2):
                print("moving onto next Authority server IP")
    if packet_received:
        print("********** AUTHORITY RESPONSE **********")
        header = packet.header
        questions = packet.questions
        answers = packet.answers
        authorities = packet.authorities
        additionals = packet.additionals
        hosts_list = []
        print("HEADER")
        print(header)
        print("QUESTIONS")
        for i in questions:
            print(i)
        print("ANSWERS")
        for i in answers:
            print(i)
            ip4 = ip4_string(i.Rdata)
            print(ip4)
            hosts_list.append(ip4)
        print("AUTHORITIES")
        for i in authorities:
            print(i)
            if(i.type ==2 and i.RDlen > 4): # auth.RDlen > 4 to filter out ip addresses labelled with type 2. Also very unlikely a domain name is two letters (1 length byte + 2 char bytes + 1 terminator byte)
                temp = BytesIO(i.Rdata)
                #print(bin(int.from_bytes(i.Rdata, byteorder="big")))
                decoded_Rdata = decode_domain_name(temp)
                if decoded_Rdata != None:
                    print(decoded_Rdata)
            else:
                ip4 = ip4_string(i.Rdata)
                print(ip4)
        print("ADDITIONALS")
        for i in additionals:
            print(i)
            if (i.RDlen == 4): # filtering for ipv4 addresses
                ip4 = ip4_string(i.Rdata)
                print(ip4)
            else: # ipv6 addresses
                print(ip6_string(i.Rdata))
        break

print('********** HOST ADDRESSES **********')
unique_hosts = list(set(hosts_list))
print(unique_hosts)
client_socket.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_tcp:
    connected = False
    start_time = time.time()
    for ip in unique_hosts:
        for i in range(3):
            try:
                client_tcp.connect((ip, 80)) # 80 is port for HTTP
                connected = True
                break
            except TimeoutError:
                print("Time out occurred")
        if connected:
            client_tcp.sendall(b"GET / HTTP/1.1\r\nHost:tmz.com\r\n\r\n")
            response = client_tcp.recv(4096)
            http_RTT = time.time() - start_time
            print('********** HTTP RESPONSE **********')
            print(response.decode())
            break


print(f"Resolver RTT: {resolver_RTT} seconds")
print(f"HTTP RTT: {http_RTT} seconds")
#dest = ('198.41.0.4', 53)
#response = send_query(client_socket, query, dest)

#print(response)
# buffer = BytesIO(response)
# header = parse_header(buffer)
# question = parse_question(buffer)
# print(header)
# print(question)
# TLD_ip = []
# print("Authority records: ")
# for i in range(header.NSCOUNT):
#     auth = parse_record(buffer)
#     print(auth)
#     if(auth.type == 2 and auth.RDlen > 4): # auth.RDlen > 4 to filter out ip addresses labelled with type 2. Also very unlikely a domain name is two letters (1 length byte + 2 char bytes + 1 terminator byte)
#         temp = BytesIO(auth.Rdata)
#         print(decode_domain_name(temp))
#     else:
#         ip4 = ip4_string(auth.Rdata)
#         print(ip4)
#         TLD_ip.append(ip4_string(auth.Rdata))
# print("Additional records: ")
# for i in range(header.ARCOUNT):
#     add = parse_record(buffer)
#     print(add)
#     if (add.RDlen == 4): # filtering for ipv4 addresses
#         ip4 = ip4_string(auth.Rdata)
#         print(ip4)
#         TLD_ip.append(ip4_string(auth.Rdata))
#     else: # ipv6 addresses
#         print(ip6_string(add.Rdata))
# print(TLD_ip)

#packet = parse_packet(response)
#print(packet)
# header = packet.header
# questions = packet.questions
# answers = packet.answers
# authorities = packet.authorities
# additionals = packet.additionals
# TLD_list = []
# print("HEADER")
# print(header)
# print("QUESTIONS")
# for i in questions:
#     print(i)
# print("ANSWERS")
# for i in answers:
#     print(i)
# print("AUTHORITIES")
# for i in authorities:
#     print(i)
#     if(i.type ==2 and i.RDlen > 4): # auth.RDlen > 4 to filter out ip addresses labelled with type 2. Also very unlikely a domain name is two letters (1 length byte + 2 char bytes + 1 terminator byte)
#         temp = BytesIO(i.Rdata)
#         #print(bin(int.from_bytes(i.Rdata, byteorder="big")))
#         decoded_Rdata = decode_domain_name(temp)
#         if decoded_Rdata != None:
#             print(decoded_Rdata)
#     else:
#         ip4 = ip4_string(i.Rdata)
#         print(ip4)
#         TLD_list.append(ip4)
# print("ADDITIONALS")
# for i in additionals:
#     print(i)
#     if (i.RDlen == 4): # filtering for ipv4 addresses
#         ip4 = ip4_string(i.Rdata)
#         print(ip4)
#         TLD_list.append(ip4)
#     else: # ipv6 addresses
#         print(ip6_string(i.Rdata))

# unique_TLD = list(set(TLD_list)) # filter out duplicate IPs
# print(unique_TLD)

# dest = ('192.41.162.30',53)
# response = send_query(client_socket, query, dest)
# packet = parse_packet(response)
# print(packet)
# header = packet.header
# questions = packet.questions
# answers = packet.answers
# authorities = packet.authorities
# additionals = packet.additionals
# authorities_list = []
# print("HEADER")
# print(header)
# print("QUESTIONS")
# for i in questions:
#     print(i)
# print("ANSWERS")
# for i in answers:
#     print(i)
# print("AUTHORITIES")
# for i in authorities:
#     print(i)
#     if(i.type ==2 and i.RDlen > 4): # auth.RDlen > 4 to filter out ip addresses labelled with type 2. Also very unlikely a domain name is two letters (1 length byte + 2 char bytes + 1 terminator byte)
#         temp = BytesIO(i.Rdata)
#         # curr = temp.tell()
#         # data = temp.read()
#         # print(data)
#         # temp.seek(curr)
#         #print(bin(int.from_bytes(i.Rdata, byteorder="big")))
#         decoded_Rdata = decode_domain_name(temp)
#         if decoded_Rdata != None:
#             print(decoded_Rdata)
#     else:
#         ip4 = ip4_string(i.Rdata)
#         print(ip4)
#         authorities_list.append(ip4)
# print("ADDITIONALS")
# for i in additionals:
#     print(i)
#     if (i.RDlen == 4): # filtering for ipv4 addresses
#         ip4 = ip4_string(i.Rdata)
#         print(ip4)
#         authorities_list.append(ip4)
#     else: # ipv6 addresses
#         print(ip6_string(i.Rdata))

# unique_authorities =  list(set(authorities_list))
# print(unique_authorities)


# dest = ('205.251.193.129',53)
# response = send_query(client_socket, query, dest)
# packet = parse_packet(response)
# print(packet)
# header = packet.header
# questions = packet.questions
# answers = packet.answers
# authorities = packet.authorities
# additionals = packet.additionals
# authorities_list = []
# print("HEADER")
# print(header)
# print("QUESTIONS")
# for i in questions:
#     print(i)
# print("ANSWERS")
# for i in answers:
#     print(i)
#     ip4 = ip4_string(i.Rdata)
#     print(ip4)