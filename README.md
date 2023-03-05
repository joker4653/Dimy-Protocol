# Digital Contact Tracing Protocol
Front-end: client  
Back-end: server 

## Tasks 
- **Task 1:** Generate a 16-Byte Ephemeral ID (EphID) after every 15 sec.  

- **Task 2:** Prepare *n* chunks of the EphID by using ***k-out-of-n* Shamir Secret Sharing** mechanism. For this implementation, we use the values of *k* and *n* to be 3 and 5 respectively.  

- **Task 3:** Broadcast these *n* shares @ 1 unique share per 3 seconds. For this implementation, you are not required to use Bluetooth message advertisement, rather you can use **simple UDP broadcasting** to advertise these shares. Also, you do not need to implement the simultaneous advertisement of EphIDs proposed in the reference paper.  

- **Task 4:** A receiver can reconstruct the advertised EphID, after it has successfully received at least *k* shares out of the *n* shares being advertised. This means that if the nodes have remained in contact for at least 9 seconds and received >= 3 shares of the same EphID, it can reconstruct the EphID. Verify the re-constructed EphID by taking hash and comparing with the hash advertised in the chunks.  

- **Task 5:** The node proceeds with applying **Diffie-Hellman key exchange** mechanism to arrive at the secret Encounter ID (EncID).  

- **Task 6:** A node, after successfully constructing the EncID, will encode EncID into a Bloom filter called Daily Bloom Filter (DBF), and delete the EncID.  

- **Task 7:** A DBF will store all EncIDs representing encounters faced during a 90-second period. A new DBF is initiated after the 90-second period and each node stores at most 6 DBFs. DBF that is older than 9 min from the current time is deleted from the node’s storage. Note that in original specifications DBF stores a day worth of EncIDs, but for this demo we will use DBF to store EncIDs received in 90-second windows.  

- **Task 8:** Every 9 minutes, a node combines all the available DBFs into another Bloom Filter called Query Bloom Filter (QBF).  

- **Task 9:** Each node sends this **QBF to the backend server**, to check whether it has come in close contact with someone who has been diagnosed positive with COVID-19. The node will receive the result of matching performed at the back-end server. The result is displayed to inform the user. You are required to use **TCP** for this communication between the node and the back-end server.  

- **Task 10:** A user who is diagnosed positive with COVID-19, can choose to upload their close contacts to the backend server. It combines all available DBF’s into a single Contact Bloom Filter (CBF) and uploads the CBF to the backend server. Once a node uploads a CBF, it stops generating the QBFs. The node will receive a confirmation that the upload has been successful.  

- **Task 11:** This task performs simple security analysis of your implementation of the DIMY protocol. There are two types of communications in the DIMY protocol: i) Nodes communicate with each other using UDP broadcasts, ii) nodes communicate with the backend server using the TCP protocol. **Create an attacker node** by modifying your implementation of the DIMY frontend. This code is named Attacker.py (or Attacker.java / Attacker.c). Assume that this node can receive all of the UDP broadcasts from other legitimate nodes. Think of one attack that can be launched by this attacker node. Implement this attack and show how this attack affects the DIMY nodes. Now focus on the communication of nodes with the backend server. Again, think of one attack that can be launched by the attacker node assuming the communication is not encrypted and the attacker node can listen to any node communicating with the backend server. Explain how this attack affects the working of the DIMY protocol. Note that you do not need to implement this attack on communication with the backend server. Finally, suggest measures (if possible) that can be implemented to prevent the attacks you identified for both types of communications.  
