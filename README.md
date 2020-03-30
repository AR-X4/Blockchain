# Blockchain

Windows command line program. Built with Java version 13.0.2.

Three processes perform work and compete to solve unverified blocks of data.  Once an unverified block is solved, the newly verified block 
is converted to a signed SHA256 JSON string, added to the blockchain, and multicast to all other processes.  

Need to download gson-2.8.2.jar into your classpath / compiling directory.

To compile:

javac -cp "gson-2.8.2.jar" Blockchain.java
Or run compileBlockchain.bat

To Run:

Run runBlockchainMaster.bat

The processes verify 12 unverified blocks of sample data.  Enter 'C' to print the number of blocks verified by each process.  Enter 'L'
to print the entire blockchain.

