# A small fuzzer i wrote for vulnserver.

##### this fuzzer is really just here to do basic binary exploitation.
##### use something like boofuzz for anything serious instead




Example Usage:


```

usage: fuzzer.py [-h] -f FUNC_TO_FUZZ -l LENGTH_OF_BUFFER -i IP -p PORT
                 [-b BAD_CHARS]
                 {func} ...

bof-exploit

positional arguments:
  {func}               func ['fuzzbc', 'testeip', 'fuzzbp']

optional arguments:
  -h, --help           show this help message and exit
  -f FUNC_TO_FUZZ      function to fuzz for example "HELLO "
  -l LENGTH_OF_BUFFER  length of buffer
  -i IP                ip
  -p PORT              port
  -b BAD_CHARS         bad chars for example "0x10,0x0a,0x0d"


```

```sh
python fuzzer.py -f "TRUN ." -l 4000 -i 192.168.138.139 -p 9999 func fuzzbp

send payload to 192.168.138.139:9999 with total length of 4000 .
the last 20 bytes of the buffer are:
41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:41:0d:0a


python fuzzer.py -f "TRUN ." -l 2018 -i 192.168.138.139 -p 9999 func testeip

send payload to 192.168.138.139:9999 with total length of 2018 .
the last 20 bytes of the buffer are:
41:41:41:41:41:41:42:42:42:42:43:43:43:43:44:44:44:44:0d:0a


python fuzzer.py -f "TRUN ." -l 2018 -i 192.168.138.139 -p 9999 func fuzzbc

send payload to 192.168.138.139:9999 with total length of 2274 .
the last 20 bytes of the buffer are:
ee:ef:f0:f1:f2:f3:f4:f5:f6:f7:f8:f9:fa:fb:fc:fd:fe:ff:0d:0a

python fuzzer.py -f "TRUN ." -l 2018 -i 192.168.138.139 -p 9999 -b "0x00" func fuzzbc

```
