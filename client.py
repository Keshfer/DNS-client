import socket
import random
from io import BytesIO
import struct
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
#DNS Question
class Question:
    def __init__(self, QNAME: bytes, QTYPE: int, QCLASS: int ):
        
        self.QNAME = QNAME     
        self.QTYPE = QTYPE
        self.QCLASS = QCLASS
    def __str__(self):
        return f"Question(QNAME: {self.QNAME}, QTYPE: {self.QTYPE}, QCLASS: {self.QCLASS})"

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
        return f"ResourceRecord(name: {self.name}, type: {self.type} class_data: {self.class_data}, TTL: {self.TTL}, RDlen: {self.RDlen}, self.Rdata: {self.Rdata})"

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

def parse_header(buffer):
    header_shorts = struct.unpack('!HHHHHH', buffer.read(12)) # 12 bytes
    return Header(header_shorts[0], header_shorts[1], header_shorts[2], header_shorts[3], header_shorts[4], header_shorts[5])

def decode_domain_name(buffer):
    chunks = []
    while (length := buffer.read(1)[0]) != 0: #checks to see if there are still domain name chunks to read. [0] is the byte that indicates how many character bytes there are
        if length & 0b11000000: #performs bitwise AND to check if there is compression.
            #length is compressed so decode it
            chunks.append(decode_compressed_domain_name(length, buffer))
            break # break because decode_compressed_domain_name will handle 
        else:
            chunks.append(buffer.read(length)) # read up to the specify length and store that name chunk in chunks
    #buffer.read will eventually reach the terminator byte and end the loop
    return b".".join(chunks)

def decode_compressed_domain_name(length, buffer):
    pointer_bytes = bytes([length & 0b00111111]) + buffer.read(1) #OFFSET is 14 bytes total which is why we do (6 + 8)
    pointer = struct.unpack("!H", pointer_bytes)[0] #[0] because struct.unpack returns a tuple "The result is a tuple even if it contains exactly one item."
    current_pos = buffer.tell()
    buffer.seek(pointer)
    decoded_name = decode_domain_name(buffer) #will perform the normal parsing (the else body of the function) of the domain name
    buffer.seek(current_pos)
    return decoded_name

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
client_socket = sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
client_socket.settimeout(10)
# for ip in root_servers:
#     client_socket.sendto(query, (ip, 53))
#     response, res_addr = client_socket.recvfrom(1024)
#     #print(response)
#     buffer = BytesIO(response)
#     header = parse_header(buffer)
#     print(header)
client_socket.sendto(query, ('198.41.0.4', 53))
response, res_addr = client_socket.recvfrom(1024)
#print(response)
buffer = BytesIO(response)
header = parse_header(buffer)
question = parse_question(buffer)
print(header)
print(question)
TLD_ip = []
print("Authority records: ")
for i in range(header.NSCOUNT):
    auth = parse_record(buffer)
    print(auth)
    if(auth.type == 2 and auth.RDlen > 4): # auth.RDlen > 4 to filter out ip addresses labelled with type 2. Also very unlikely a domain name is two letters (1 length byte + 2 char bytes + 1 terminator byte)
        temp = BytesIO(auth.Rdata)
        print(decode_domain_name(temp))
    else:
        print(ip4_string(auth.Rdata))
print("Additional records: ")
for i in range(header.ARCOUNT):
    add = parse_record(buffer)
    print(add)
    print(add.RDlen)
    if (add.RDlen == 4): # filtering for ipv4 addresses
        print(ip4_string(add.Rdata))
    else: # ipv6 addresses
        print(ip6_string(add.Rdata))

