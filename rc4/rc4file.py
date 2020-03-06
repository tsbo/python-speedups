import argparse
import sys
import os
import getpass
#import timeit
import time

from rc4 import *

BUF_SIZE = 128 * 1024

print 'rc4file.py - a tool for file encryption/decryption using RC4'
print ''

parser = argparse.ArgumentParser()

parser.add_argument('--key', '-k', action='store', dest='key', default='', 
        help='use key for encryption/decryption using RC4')

parser.add_argument('--infile', '-i', action='store', dest='input', default='', 
        help='input file')

parser.add_argument('--outfile', '-o', action='store', dest='output', default='', 
        help='output file')

config = parser.parse_args()

if len(sys.argv) < 2:
    parser.print_help()
    sys.exit(0)

if len(config.key) < 1:
    config.key = getpass.getpass('Enter key:')
    key2 = getpass.getpass('Enter key (again):')
    if config.key <> key2:
        print 'Error: Password does not match!'
        sys.exit(2)
    
if len(config.input) < 1 or len(config.output) < 1:
    print 'Error: input/output files are not specified!'
    sys.exit(2)

if not os.path.exists(config.input):
    print 'Error: input file does not exist!'
    sys.exit(2)

coder = NaiveRC4(config.key)
outf = open(config.output, 'wb')
inf = open(config.input, 'rb')

filesize=0
start_time = time.time()
buf = inf.read(BUF_SIZE)   
while buf:
#    print 'r', timeit.timeit()
    processed = coder.process_inline([ord (x) for x in buf])
#    print 'p', timeit.timeit()
    outf.write("".join([chr(x) for x in processed]))
    filesize += len(processed)
#    print 'w', timeit.timeit()
    buf = inf.read(BUF_SIZE)

print 'processed %d bytes in %.2f seconds' % (filesize, time.time() - start_time)
