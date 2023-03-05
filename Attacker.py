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
import os

# ---------------------------------------------------------------------------------------------------
# GLOBAL VARIABLES - accissible across threads 

# global tcpPort 
# global udpPort 
global shared_key
global node_private_key
global current_digest
global last_digest 
global status 

tcpPort = 55000
udpPort = 8080

filterSize = 50 # 100000
filterHash = 3
dailyBF = [0] * filterSize

dailyFilters = []
receivedShares = {}
reconstructedIDs = {}
keyExchange = {}
sharedKeys = []
digests_seen = []

# ---------------------------------------------------------------------------------------------------
# RECEIVING THREAD - reveive shares, recombine EphID and derive secret shared key 

# Thread for UDP receiver
# Runs in background 
def nodeThreadRecv(udpPort):
    # print("UDP receiver thread")
    # UDP recv socket
    audienceSocket = socket(AF_INET, SOCK_DGRAM)
    audienceSocket.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
    audienceSocket.bind(('', udpPort))
    # UDP recv thread - UDP server 
    recvThread = threading.Thread(target=recv, args=(audienceSocket,))
    recvThread.daemon = True 
    recvThread.start() 

# Receiving data through UDP socket 
# Always listen on the background 
def recv(audienceSocket): 
    global current_digest
    global status
    # keep listening 
    while True:
        # only listen when status negative 
        if status == "negative":
            # get data from sender
            data, address = audienceSocket.recvfrom(1024)
            digest = data[:16]
            share = data[16:]

            # if the digest received is not the same as current digest 
            # then it is coming from another node 
            # if digest != current_digest:
            #     # print(f"Received share for digest {binascii.hexlify(digest)}")
            #     # add only digests that has not yet been reconstructed 
            #     if digest not in receivedShares and digest not in digests_seen:
            #             receivedShares[digest] = set()

            #     if digest in receivedShares:
            #         receivedShares[digest].add(share)
            #         # when at least 3 shares, reconstruct 
            #         if (len(receivedShares[digest]) >= 3): 
            #             reconstruct_shares(digest)

            # # clear up the seen digest list 
            # if len(digests_seen) == 10:
            #     digests_seen.clear()


def reconstruct_shares(digest): 
    global node_private_key
    reconstruct = []

    for share in receivedShares[digest]: 
        encoded = subrosa.Share.from_bytes(share)
        reconstruct.append(encoded)

    # reconstrcut the EphID 
    sender_public_key_bytes = subrosa.recover_secret(reconstruct)
    # hash of a reconstructed EphID
    recHash = hashlib.md5(sender_public_key_bytes).digest()
    
    # check if digest same as hash 
    if digest == recHash: 
        # decode serialized key
        sender_public_key_decoded = serialization.load_der_public_key(sender_public_key_bytes)
        # # generate the shared key - EncID 
        shared_key = node_private_key.exchange(sender_public_key_decoded)
        # if reconstructed for this digest, then add it to list 
        digests_seen.append(digest)
        # print(f">>> derived shared key for digest {binascii.hexlify(digest)}")
        # print(">>>", binascii.hexlify(shared_key))
        
        # encode the shared key to DBF 
        if encode_to_dailyBF(shared_key): 
            print(f"Successfully encoded {binascii.hexlify(shared_key)} to DBF.")

        # clear list to remove all the previous shares 
        reconstruct.clear() 
        del receivedShares[digest]

def encode_to_dailyBF(shared_key):
    for i in range(filterHash):
        index = mmh3.hash(shared_key, i) % filterSize
        dailyBF[index] = 1
    return True 

# ---------------------------------------------------------------------------------------------------
# SENDING THREAD - generate private/public (EphID) keys, Shamir's secret and broadcast EphID shares

# UDP send thread
def senderThreadSend(udpPort):
    global presenterSocket
    # print("Main UDP sender thread")
    # UDP send socket
    presenterSocket = socket(AF_INET, SOCK_DGRAM)
    presenterSocket.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
    presenterSocket.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    # UDP sending thread 
    sendThread = threading.Thread(target=broadcast, args=(presenterSocket, udpPort))
    sendThread.start() 
    time.sleep(0.1)

# UPD client, broadcasts shares to other clients 
def broadcast(presenterSocket, udpPort):
    # global dailyBF
    global current_digest
    global status

    while True:
        # only broadcast when the person is negative 
        if status == "negative": 
            
            count = 0
            # set time end after 15 sec 
            attackEnd = time.time() + 3

            # while 15 sec did not pass, broadcast shares 
            while time.time() < attackEnd:
                # create private/public keys, digest and shares of a EphID 
                digest, shares = generate_keys()
                # set digest to current 
                current_digest = digest
                
                for share in shares:
                    # combine current digest and its shares for broadcast 
                    packed = digest + share
                    # always send the packet 
                    presenterSocket.sendto(packed, ('<broadcast>', udpPort))
                    print(f"packet #{count} sent")
                    count += 1 

            # ones time expired, offer repeat or exit 
            repeat = input("Attack completed. Repeat? ")
            if repeat == "yes": 
                continue
            if repeat == "no": 
                os._exit(1)
            
            # generate the status and either send QBF or CBF
            # status_update()

        # if node is positive, wait and reset to negative 
        # does not broadcast nor receives at this time 
        # else:
        #     time.sleep(50)
        #     print("    > Resetting status to negative...")
        #     status = "negative"

def status_update(): 
    global status 
    # generate status at random with probabilities 80/20
    status = np.random.choice(["negative", "positive"], p=[0.8, 0.2])

    # if the status if negative, send QBF 
    if status == "negative": 
        # print("    * Node is negative")
        # at most 6 filters, remove first one if reached limit
        if len(dailyFilters) == 2: # should be 6  
            # combine to Query Bloom Filter 
            if encode_to_queryBF(): 
                dailyFilters.clear()
        # keep track of how many filters there are 
        dailyFilters.append(dailyBF)

    # without waiting for 6 DBFs, if the user status "positive"
    # then combine all the available DBFs and send to the server 
    if status == "positive": 
        print("    * Node is positive")
        # ones the CBF was successfully uploaded to the server, close thread 
        if encode_to_contactBF():
            print("CBF was successfully stored on server. Closing thread.")

def encode_to_contactBF(): 
    # combine all DBF to CBF with logical OR 
    contractBF = bytearray([int(any(l)) for l in zip(*dailyFilters)])
    # successfully encoded to QBF 
    print("    * Successfully encoded all DBFs to CBF.")
    # send the BF to server to store 
    if threadTCP(contractBF, 1):
        # return true and close the thred - stop sending QBFs 
        return True 

def encode_to_queryBF():
    # combine all DBF to QBF with logical OR 
    queryBF = bytearray([int(any(l)) for l in zip(*dailyFilters)])
    # successfully encoded to QBF 
    print("    * Successfully encoded all DBFs to QBF.")
    # start server thread 
    if threadTCP(queryBF, 2):
        return True     

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
    # code 1 = positive 
    # code 2 = negative

    # send CBF to the server and store 
    if code == 1: 
        clientSocket.send(code.to_bytes(4, byteorder='big') + bytes)
        print("    > Client sent CBF to server...")
        # receive response from server 
        response = clientSocket.recv(2048).decode('utf-8')
        # successfully stored on server, close this thread and return 
        if response == 0:
            print("    > CBF was successfully stored.")

    # send QBF to the server and do not store, return matching results 
    if code == 2:
        # clientSocket.send(code.to_bytes(4, byteorder='big'))
        clientSocket.send(code.to_bytes(4, byteorder='big') + bytes)
        print("    > Client sent QBF to server...")

        # receive response from server 
        response = clientSocket.recv(2048).decode('utf-8')
        # no match was found 
        if response == "no match":
            print("    > No match was found for the recent QBF.")

        if response == "match": 
            print("    > Match was found for the recent QBF.")
        
    time.sleep(0.5)
    clientSocket.close()
    return True 

    # close the connection to server ?
    

# ---------------------------------------------------------------------------------------------------
# MAIN START - start threads here 

def connection(): 
    global status
    # get random node ID to determine who shares belong to
    # nodeID = uuid.uuid4()

    # set default as negative 
    status = "negative"

    time.sleep(1) 
    
    nodeThreadRecv(udpPort)
    senderThreadSend(udpPort)

    # connect to server 
    # threadTCP(tcpPort)

if __name__ == "__main__":
    # start the node connection 
    connection()
    while True: 
        time.sleep(0.1)