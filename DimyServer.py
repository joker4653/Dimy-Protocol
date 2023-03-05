# Backend Server 

from socket import * 
import sys 
import threading

# Create server socket 
serverSocket = socket(AF_INET, SOCK_STREAM)
# Bind port number to the server's socket 
serverSocket.bind(('', 55000))

global globalCBF

# Handle multiple clients
def handleClient(connectionSocket, address):
    global globalCBF
    connection = True 

    response_positive = "match"
    response_negative = "no match"
    success = "stored"

    print(f"New connection {address} connected.")
    
    # receive QBF or CBF from client 
    data = connectionSocket.recv(800004, MSG_WAITALL)
    
    code = int.from_bytes(data[:4], byteorder='big')
    bytes = data[4:]

    # received CBF 
    # when positive 
    if code == 1: 
        newly_CBF = [x or y for x, y in zip(globalCBF, list(bytes))]
        globalCBF = newly_CBF

        print(f"{address[1]}, code {code}: Successfully stored CBF on server.")
        # ones stored, send back success check 
        connectionSocket.send(success.encode('utf-8'))

    # received QBF -> perform matching 
    # when negative 
    if code == 2: 
        print(f"{address[1]}, code {code}: Received QBF from client.")
        if len(globalCBF) > 0: 
            # do the matching 
            matching = [int(any(l)) for l in zip(globalCBF, list(bytes))]
            # if match found, set flag as positive  
            if matching.count(1) >= 3: 
                print(f"{address[1]}, code {code}: The QBF matches stored CBF by at least 3 indexes.")
                connectionSocket.send(response_positive.encode('utf-8'))
            # no match was found 
            else: 
                print(f"{address[1]}, code {code}: The QBF does not match any CBF stored.")
                connectionSocket.send(response_negative.encode('utf-8'))
        # nothing to match 
        else: 
            print(f"{address[1]}, code {code}: No CBFs stored, nothing to match.")
            connectionSocket.send(response_negative.encode('utf-8'))

    print("")
    connectionSocket.close() 

# multi-threaded listening to client 
def start():
    global globalCBF
    globalCBF = bytearray([0] * 800000)
    serverSocket.listen(3)
    print("Server listening...")
    while True:
        connectionSocket, address = serverSocket.accept()
        thread = threading.Thread(target=handleClient, args=(connectionSocket, address))
        thread.daemon = True 
        thread.start()

try:
    start()
except KeyboardInterrupt:
    print("\nServer has been shut down.")