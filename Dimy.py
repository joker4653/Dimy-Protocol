from socket import * 
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives import serialization

import numpy as np
import threading
import binascii
import hashlib
import subrosa
import random 
import time 
import mmh3

# ---------------------------------------------------------------------------------------------------
# GLOBAL VARIABLES - accissible across threads 
global shared_key
global node_private_key
global current_digest
global last_digest 
global status 
global dailyBF_id
global dailyBF
global round 

tcpPort = 55000
udpPort = 8080

filterSize = 800000 
filterHash = 3

dailyFilters = []
receivedShares = {}
reconstructedIDs = {}
keyExchange = {}
sharedKeys = []
digests_seen = []

# ---------------------------------------------------------------------------------------------------
# RECEIVING THREAD - reveive shares, recombine EphID and derive secret shared key 

# Thread for UDP receiver, runs in background 
def nodeThreadRecv(udpPort):
    # UDP recv socket
    audienceSocket = socket(AF_INET, SOCK_DGRAM)
    audienceSocket.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
    audienceSocket.bind(('', udpPort))
    # UDP recv thread - UDP server 
    recvThread = threading.Thread(target=recv, args=(audienceSocket,))
    recvThread.daemon = True 
    recvThread.start() 

# Receiving data through UDP socket, always listen on the background 
def recv(audienceSocket): 
    global current_digest
    global status
    # delay start to avoid errors 
    time.sleep(0.1) 

    while True:
        # only listen when status negative 
        if status == "negative":
            # get data from sender
            data, address = audienceSocket.recvfrom(1024)
            digest = data[:16]
            share = data[16:]

            try:
                # if the digest received is not the same as current digest 
                # then it is coming from another node 
                if digest != current_digest and status == "negative":
                    print(f"     > received share")
                    # add only digests that has not yet been reconstructed 
                    if digest not in receivedShares and digest not in digests_seen:
                            receivedShares[digest] = set()

                    if digest in receivedShares:
                        receivedShares[digest].add(share) 
                        # when at least 3 shares, reconstruct 
                        if (len(receivedShares[digest]) >= 3): 
                            reconstruct_shares(digest)

                # clear up the seen digest list 
                if len(digests_seen) == 10:
                    digests_seen.clear()

            # the thread haven't produced first digest yet 
            except NameError:
                continue 

        # once positive, close the thread 
        if status == "positive": 
            audienceSocket.close()
            return 

def reconstruct_shares(digest): 
    global node_private_key
    reconstruct = []

    print("\nnumber of shares is 3, attempt reconstruction of EphID")

    for share in receivedShares[digest]: 
        encoded = subrosa.Share.from_bytes(share)
        reconstruct.append(encoded)

    # reconstrcut the EphID 
    sender_public_key_bytes = subrosa.recover_secret(reconstruct)
    # hash of a reconstructed EphID
    recHash = hashlib.md5(sender_public_key_bytes).digest()
    
    # check if digest same as hash 
    if digest == recHash: 
        print("^ reconstructed and verified EphID")
        # decode serialized key
        sender_public_key_decoded = serialization.load_der_public_key(sender_public_key_bytes)
        # # generate the shared key - EncID 
        shared_key = node_private_key.exchange(sender_public_key_decoded)
        # if reconstructed for this digest, then add it to list 
        digests_seen.append(digest)

        print(f"^ computed EncID {binascii.hexlify(shared_key)}")
        # encode the shared key to DBF 
        encode_to_dailyBF(shared_key)

        # clear list to remove all the previous shares 
        reconstruct.clear() 
        if digest in receivedShares:
            del receivedShares[digest]
        print("^ deleted EncID\n")

def encode_to_dailyBF(shared_key):
    global dailyBF
    indexes = []
    for i in range(filterHash):
        index = mmh3.hash(shared_key, i) % filterSize
        indexes.append(index)
        dailyBF[index] = 1
    print(f"^ encoded EncID to DBF #{len(dailyFilters)} with indexes {indexes}")

# ---------------------------------------------------------------------------------------------------
# SENDING THREAD - generate private/public (EphID) keys, Shamir's secret and broadcast EphID shares

# UDP send thread
def senderThreadSend(udpPort):
    global presenterSocket
    # UDP send socket
    presenterSocket = socket(AF_INET, SOCK_DGRAM)
    presenterSocket.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
    presenterSocket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    # UDP sending thread 
    sendThread = threading.Thread(target=broadcast, args=(presenterSocket, udpPort))
    sendThread.start() 
    time.sleep(0.1)

def queryThread():
    queryThread = threading.Thread(target=bloom_filters)
    queryThread.daemon = True
    queryThread.start() 
    time.sleep(0.1)

def bloom_filters():
    global dailyBF_id
    global dailyBF
    global round 
    round = 1

    while True: 
        # timer for 9 minutes to generate QBF 
        QBFEnd = time.time() + 540
        # once timer experied, encode to QBF and set again 
        while time.time() < QBFEnd:
            # time until DBF filled up
            DBFEnd = time.time() + 90
            # initiate reset of daily bloom filter of size 100kb
            dailyBF = [0] * filterSize
            while time.time() < DBFEnd:
                continue 
            # 90 sec passed, add old DBF to the list, generate new DBF and increase count 
            dailyFilters.append(dailyBF)
            dailyBF_id += 1
            round += 1
        print(f"     * reaches DBF limit {len(dailyFilters)}")
        # combine to Query Bloom Filter 
        encode_to_queryBF()
        dailyBF = [0] * filterSize
        # reset count to zero 
        dailyBF_id = 0


# UPD client, broadcasts shares to other clients 
def broadcast(presenterSocket, udpPort):
    global current_digest
    global status
    global round 

    while True:
        # timer to randomly generate covid status 
        statusTimer = time.time() + 90 

        while time.time() < statusTimer:
            # generate status at random with probabilities 90/10
            status = np.random.choice(["negative", "positive"], p=[0.95, 0.05])

            # track if this is the first round, then just proceed 
            if round == 1: status = "negative"
            # without waiting for 6 DBFs, if the user status "positive" combine all the available DBFs
            if status == "positive": 
                print("     ********************")
                print("     * node is positive *")
                print("     ********************")
                # ones the CBF was successfully uploaded to the server, close thread 
                encode_to_contactBF()
                # if node is positive, wait and reset to negative 
                time.sleep(40)
                print("     * resetting status to negative...\n")
                status = "negative"
                # restart the listening thread 
                nodeThreadRecv(udpPort)
                continue 

            print("****** generated a new EphID")
            # create private/public keys, digest and shares of a EphID 
            digest, shares = generate_keys()
            # set digest to current 
            current_digest = digest
            # set time end after 15 sec 
            EphIDEnd = time.time() + 15

            # while 15 sec did not pass, broadcast shares 
            while time.time() < EphIDEnd:
                for share in shares:
                    # combine current digest and its shares for broadcast 
                    packed = digest + share
                    # random number between 0 and 1 - if no drop, then arrives to the same share everytime 
                    rand = random.uniform(0, 1)
                    if rand > 0.5: 
                        presenterSocket.sendto(packed, ('<broadcast>', udpPort))
                        print(f"     * share was broadcasted       | drop: {rand:.3f}")
                    else: 
                        print(f"     * share was not broadcasted   | drop: {rand:.3f}")
                    # broadcast 1 share per 3 seconds
                    time.sleep(3)
        
def encode_to_contactBF(): 
    # combine all DBF to CBF with logical OR 
    contractBF = bytearray([int(any(l)) for l in zip(*dailyFilters)])
    # successfully encoded to QBF 
    print("     * successfully encoded all DBFs to CBF")
    # send the BF to server to store 
    threadTCP(contractBF, 1)

def encode_to_queryBF():
    # combine all DBF to QBF with logical OR 
    queryBF = bytearray([int(any(l)) for l in zip(*dailyFilters)])
    # clear up the current DBF 
    dailyFilters.clear()
    # successfully encoded to QBF 
    print("     * successfully encoded all DBFs to QBF")
    # start server thread  
    threadTCP(queryBF, 2)

# generated private/public keys at each node 
# shares = public key are broadcasted to all nodes
def generate_keys():
    global node_private_key
    # generate 32-bytes private key 
    node_private_key = X25519PrivateKey.generate()
    # create a public key from private key, which is EphID
    node_public_key = node_private_key.public_key()
    # serialise public key to bytes 
    node_public_key_bytes = node_public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    # get digest 
    digest = hashlib.md5(node_public_key_bytes).digest()
    # split on shares the public key 
    shares_raw = subrosa.split_secret(node_public_key_bytes, 3, 5)
    # convert shares to bytes 
    shares = [bytes(share) for share in shares_raw]
    print("     * generated 5 shares of EphID")
    return (digest, shares)

# ---------------------------------------------------------------------------------------------------
# TCP THREAD 

# Main thread for TCP client 
def threadTCP(bytes, code):
    global clientSocket 
    # TCP send socket
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect(('', tcpPort))
    # TCP main client thread 
    mainThread = threading.Thread(target=tcp, args=(bytes, code))
    mainThread.daemon = True
    mainThread.start()

def tcp(bytes, code): 
    # code 1 = positive, code 2 = negative
    time.sleep(0.1)
    # send CBF to the server and store 
    if code == 1: 
        clientSocket.send(code.to_bytes(4, byteorder='big') + bytes)
        print("     > client sent CBF to server...")
    # send QBF to the server and do not store, return matching results 
    elif code == 2:
        # clientSocket.send(code.to_bytes(4, byteorder='big'))
        clientSocket.send(code.to_bytes(4, byteorder='big') + bytes)
        print("     > client sent QBF to server...")

    # receive response from server 
    response = clientSocket.recv(2048).decode('utf-8')
    time.sleep(0.1)

    if response == "stored":
        print("     > CBF was successfully stored")
    # no match was found 
    elif response == "no match":
        print("          > no match was found for the recent QBF\n")
    elif response == "match": 
        print("          > match was found for the recent QBF\n")

    time.sleep(0.5)
    return True 


# ---------------------------------------------------------------------------------------------------
# MAIN START - start threads here 

def connection(): 
    global status
    global dailyBF_id
    global dailyBF
    global current_digest

    # set default as negative 
    status = "negative"
    dailyBF_id = 0
    dailyBF = [0] * filterSize

    # just a small delay before start
    time.sleep(1) 

    # start receving and sending threads 
    queryThread()
    nodeThreadRecv(udpPort)
    senderThreadSend(udpPort)
    

if __name__ == "__main__":
    # start the node connection 
    connection()
    while True: 
        time.sleep(0.1)