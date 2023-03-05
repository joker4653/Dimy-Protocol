
from socket import * 

import threading
import time 
import sys
import os 


# Main thread for TCP client connection to server 
def threadTCP(tcpPort):
    global clientSocket 
    print("TCP thread")
    # TCP send socket
    clientSocket = socket(AF_INET, SOCK_STREAM)
    clientSocket.connect(('', tcpPort))
    # TCP main client thread 
    mainThread = threading.Thread(target=connectionTCP)
    mainThread.daemon = True
    mainThread.start()

# Main TCP thread connected to server 
def connectionTCP():
    print("Connected to server using TCP")

    # anything to send / recieve from server 
    message = "some test data for server"
    clientSocket.send(message.encode('utf-8'))
    response = clientSocket.recv(2048).decode('utf-8')
    print("Response form server:", response)

    time.sleep(15)
    
    # close threads and exit 
    # os._exit(1) 
