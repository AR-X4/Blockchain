/* 

Author: Andrew Richards 2/28/20
Java version 13.0.2


The web sources:

https://mkyong.com/java/how-to-parse-json-with-gson/
http://www.java2s.com/Code/Java/Security/SignatureSignAndVerify.htm
https://www.mkyong.com/java/java-digital-signatures-example/ (not so clear)
https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/
https://www.programcreek.com/java-api-examples/index.php?api=java.security.SecureRandom
https://www.mkyong.com/java/java-sha-hashing-example/
https://stackoverflow.com/questions/19818550/java-retrieve-the-actual-value-of-the-public-key-from-the-keypair-object
https://www.java67.com/2014/10/how-to-pad-numbers-with-leading-zeroes-in-Java-example.html

One version of the JSON jar file here:
https://repo1.maven.org/maven2/com/google/code/gson/gson/2.8.2/

Need to download gson-2.8.2.jar into your classpath / compiling directory.

To compile:

javac -cp "gson-2.8.2.jar" Blockchain.java
Or run compileBlockchain.bat

To Run:

Run runBlockchainMaster.bat

-----------------------------------------------------------------------------------------------------*/

import java.util.*;
import java.io.*;
import java.net.*;
import java.util.concurrent.*;
import java.lang.reflect.Type;
import java.security.*;
import java.time.Instant;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

class Ports {
	protected static int KeyServerPortBase = 4710;
	protected static int UnverifiedBlockServerPortBase = 4820;
	protected static int BlockchainServerPortBase = 4930;

	protected static int KeyServerPort;
	protected static int UnverifiedBlockServerPort;
	protected static int BlockchainServerPort;

	protected void setPorts(){
		KeyServerPort = KeyServerPortBase + Blockchain.PID;
		UnverifiedBlockServerPort = UnverifiedBlockServerPortBase + Blockchain.PID;
		BlockchainServerPort = BlockchainServerPortBase + Blockchain.PID;
	}
}

class PublicKeyWorker extends Thread {
	private Socket sock;
	PublicKeyWorker (Socket s) {
		sock = s;
	}

	public void run() {
		try{
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream())); 
			Integer PID = Integer.valueOf(in.readLine());
			String data = in.readLine();
			
			System.out.println("Public Key Server Got Key: " + data + " from Process: " + PID + "\n");
			Blockchain.PublicKeys.put(PID, data);
			sock.close();
		} 	
		catch (IOException e) {
			e.printStackTrace();
		}
	}
}

class PublicKeyServer implements Runnable {

	public void run() {
		
		Socket sock;
		System.out.println("Starting Key Server input thread using: " + Ports.KeyServerPort);
		try {
			ServerSocket servsock = new ServerSocket(Ports.KeyServerPort, Blockchain.q_len);
			while (true){
				sock = servsock.accept();
				new PublicKeyWorker (sock).start();
			}
		} 
		catch (IOException e) {
			e.printStackTrace();
		}
	}
}

class BlockRecord implements Comparable {
  
  private String Timestamp;
  private String BlockID;
  private String VerificationProcessID;
  private String PreviousHash;
  private UUID uuid;
  private String SignedSHA256;
  private String SHA256String;
  private String CreatingProcess;
  private String BlockData;
  private String Fname;
  private String Lname;
  private String SSNum;
  private String DOB;
  private String Diag;
  private String Treat;
  private String Rx;

  //-----accessor methods-----
  protected String getPreviousHash() {return this.PreviousHash;}
  protected void setPreviousHash(String previousHash){this.PreviousHash = previousHash;}
  
  protected UUID getUUID() {return uuid;}
  protected void setUUID (UUID ud){this.uuid = ud;}
  
  protected String getBlockData() {return this.BlockData;}
  protected void setBlockData(String blockData){this.BlockData = blockData;}
  
  protected String getTimestamp() {return Timestamp;}
  protected void setTimestamp(String TS){this.Timestamp = TS;}
  
  protected String getSHA256String() {return SHA256String;}
  protected void setSHA256String(String SH){this.SHA256String = SH;}
  
  protected String getSignedSHA256() {return SignedSHA256;}
  protected void setSignedSHA256(String SH){this.SignedSHA256 = SH;}
  
  protected String getCreatingProcess() {return CreatingProcess;}
  protected void setCreatingProcess(String CP){this.CreatingProcess = CP;}
  
  protected String getVerificationProcessID() {return VerificationProcessID;}
  protected void setVerificationProcessID(String VID){this.VerificationProcessID = VID;}
  
  protected String getBlockID() {return BlockID;}
  protected void setBlockID(String BID){this.BlockID = BID;}
  
  protected String getSSNum() {return SSNum;}
  protected void setSSNum(String SS){this.SSNum = SS;}
  
  protected String getFname() {return this.Fname;}
  protected void setFname(String FN){this.Fname = FN;}
  
  protected String getLname() {return Lname;}
  protected void setLname(String LN){this.Lname = LN;}
  
  protected String getFDOB() {return DOB;}
  protected void setFDOB(String DOB){this.DOB = DOB;}
  
  protected String getGDiag() {return Diag;}
  protected void setGDiag(String D){this.Diag = D;}
  
  protected String getGTreat() {return Treat;}
  protected void setGTreat(String D){this.Treat = D;}
  
  protected String getGRx() {return Rx;}
  protected void setGRx(String D){this.Rx = D;}

  
  @Override
  public int compareTo(Object o) {

    BlockRecord other = (BlockRecord) o;

    Instant otherInstant = Instant.parse(other.getTimestamp());
    Instant thisInstant = Instant.parse(this.getTimestamp());

    return thisInstant.compareTo(otherInstant);
  }
}

class BlockInput {

	private static String FILENAME;

	/* Token indexes for input: */
	private static final int iFNAME = 0;
	private static final int iLNAME = 1;
	private static final int iDOB = 2;
	private static final int iSSNUM = 3;
	private static final int iDIAG = 4;
	private static final int iTREAT = 5;
	private static final int iRX = 6;
	
	protected static LinkedList<String> GetJsonListString(int pid) throws Exception {

		String result;

		// CDE: Process numbers and port numbers to be used: 
		int pnum = pid;
		int UnverifiedBlockPort;
		int BlockChainPort;
		
		UnverifiedBlockPort = 4820 + pnum;
		BlockChainPort = 4930 + pnum;

		System.out.println("Process number: " + pnum + " Unverified Server Port: " + UnverifiedBlockPort + " Blockchain Server Port: " + BlockChainPort + "\n");

		switch(pnum) {
			case 1: FILENAME = "BlockInput1.txt"; break;
			case 2: FILENAME = "BlockInput2.txt"; break;
			default: FILENAME= "BlockInput0.txt"; break;
		}

		System.out.println("Using input file: " + FILENAME);
		System.out.println("Names read into a linked list from the data input file:\n");
		try{
			BufferedReader br = new BufferedReader(new FileReader(FILENAME));
			String[] tokens = new String[10];
			String InputLineStr;
			String suuid;
			UUID idA;

			//------------create blockchain list from data input file---------
			LinkedList<String> BlockList = new LinkedList<String>();
			
			while ((InputLineStr = br.readLine()) != null) {
				
				BlockRecord BR = new BlockRecord();
				String TS = Instant.now().toString();
				BR.setTimestamp(TS);
				BR.setSHA256String("");
				BR.setSignedSHA256("");
				
				//idA = UUID.randomUUID();
				suuid = UUID.randomUUID().toString();
				BR.setBlockID(suuid);
				BR.setCreatingProcess("Process" + pnum);
				BR.setVerificationProcessID("To be set later...");
				tokens = InputLineStr.split(" +"); // Tokenize the input
				BR.setSSNum(tokens[iSSNUM]);
				BR.setFname(tokens[iFNAME]);
				BR.setLname(tokens[iLNAME]);
				BR.setFDOB(tokens[iDOB]);
				BR.setGDiag(tokens[iDIAG]);
				BR.setGTreat(tokens[iTREAT]);
				BR.setGRx(tokens[iRX]);
				
				String jsonRecord = Blockchain.gson.toJson(BR);
				BlockList.add(jsonRecord);
				
				System.out.println(tokens[iFNAME] + " " + tokens[iLNAME]);
			}
			System.out.println("\n" + BlockList.size() + " records read.\n");

			return BlockList;
		} 
		catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
}

class WorkB {

	private static final String ALPHA_NUMERIC_STRING = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	static String someText = "one two three";
	static String randString;

	private static String randomAlphaNumeric(int count) {
		StringBuilder builder = new StringBuilder();
		while (count-- != 0) {
			int character = (int)(Math.random()*ALPHA_NUMERIC_STRING.length());
			builder.append(ALPHA_NUMERIC_STRING.charAt(character));
		}
		return builder.toString();
	}

	private static String makeSHA256Digest(String input) throws Exception {

		MessageDigest MD = MessageDigest.getInstance("SHA-256");
		byte[] byteData = MD.digest(input.getBytes("UTF-8"));

		// Turn into a string of hex values
		String SHA256String = "";
		
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < byteData.length; i++) {
			sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
		}
		
		SHA256String = sb.toString();
		
		return SHA256String;
	}
	private static String signSHA256(byte[] data, PrivateKey key) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initSign(key);
		signer.update(data);
		
		return Base64.getEncoder().encodeToString(signer.sign());
	}

	protected static BlockRecord Verify(BlockRecord inputBlock, int PID) throws Exception {
		String concatString;  // Random seed string concatenated with the existing data
		String StringOut; // Will contain the new SHA256 string converted to HEX and printable.
		int workNumber;

		
		try {
			for(int i=1; i<20; i++) { 
			
				randString = randomAlphaNumeric(8);

				inputBlock.setBlockData(randString);
				concatString = Blockchain.gson.toJson(inputBlock);
				StringOut = makeSHA256Digest(concatString);
				
				
				System.out.println("Trying to Verify Input Block...\n");
				System.out.println("Hash is: " + StringOut);

				// Between 0000 (0) and FFFF (65535)
				workNumber = Integer.parseInt(StringOut.substring(0,4),16);

				System.out.println("First 16 bits in Hex and Decimal: " + StringOut.substring(0,4) +" and " + workNumber);
				
				String tmp = inputBlock.getBlockID();
				if(Blockchain.blockchain.contains(tmp)){
					System.out.println("\n------VERIFICATION ABORTED------\n");
					return null;
				}
				else if (!(workNumber < 20000)) {  // lower number = more work.
					System.out.format("%d is not less than 20,000 so we did not solve the puzzle\n\n", workNumber);
				}
				else if (workNumber < 20000) {
					System.out.format("%d IS less than 20,000 so puzzle solved!\n", workNumber);
					System.out.println("The seed (puzzle answer) was: " + randString + "\n");
					
					inputBlock.setSHA256String(StringOut);
					String hashInput = StringOut;// + PID;//???
					
					inputBlock.setSignedSHA256(signSHA256(hashInput.getBytes(), Blockchain.keyPair.getPrivate()));
					
					return inputBlock;
				}
				Thread.sleep(1000);
			}
			
		} 
		catch(Exception ex) {
			ex.printStackTrace();
		}
		return null;
	}
}

class UnverifiedBlockServer implements Runnable {
	private BlockingQueue<BlockRecord> queue;
	
	UnverifiedBlockServer(BlockingQueue<BlockRecord> queue){
		this.queue = queue;
	}

  /* Inner class to share priority queue. We are going to place the unverified blocks into this queue in the order we get
     them, but they will be retrieved by a consumer process sorted by blockID. */

	class UnverifiedBlockWorker extends Thread {
		private Socket sock;
		UnverifiedBlockWorker(Socket s){
			sock = s;
		}

		public void run(){
			try{
				BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
				String data = in.readLine();
				data = data.substring(6);
				data = data.replace("--linebreak--", "\n");
				
				BlockRecord blockRecord = this.UnMarshallJSON(data);

				//System.out.println("Unverified Block Worker Put Block in priority queue: " + data + "\n");
				queue.put(blockRecord);
			} 
			catch (Exception e) {
				e.printStackTrace();
			}
		}
		
		private BlockRecord UnMarshallJSON(String data){
			
			// Read and convert JSON File to a Java Object:
			BlockRecord blockRecordIn = Blockchain.gson.fromJson(data, BlockRecord.class);
	  
			// Print the blockRecord:
			System.out.println("Unverified Block Server: Incoming Block " + blockRecordIn + 
			"\nName is: " + blockRecordIn.getFname() + " " + blockRecordIn.getLname() + 
			"\nString UUID: " + blockRecordIn.getBlockID() + " Stored-binaryUUID: " + blockRecordIn.getUUID() + "\n");
			
			return blockRecordIn;
		}
	}
	
	public void run(){
		
		Socket sock;
		System.out.println("Starting the Unverified Block Server input thread using " + Ports.UnverifiedBlockServerPort);
		try {
			ServerSocket servsock = new ServerSocket(Ports.UnverifiedBlockServerPort, Blockchain.q_len);
			while (true) {
				sock = servsock.accept(); // Got a new unverified block
				new UnverifiedBlockWorker(sock).start(); // So start a thread to process it.
			}
		} 
		catch (IOException e) {
			System.out.println(e);
		}
	}
}

class UnverifiedBlockConsumer implements Runnable {
	private BlockingQueue<BlockRecord> queue;
	private int PID;
	UnverifiedBlockConsumer(BlockingQueue<BlockRecord> queue, int PID){
		this.queue = queue;
		this.PID = PID;
	}

	public void run(){
		BlockRecord data;
		PrintStream toServer;
		Socket sock;
		BlockRecord VerifiedBlock;
		String NewBlockchain;

		System.out.println("Starting the Unverified Block Priority Queue Consumer thread.\n");
		try{
			while(true){ // Consume from the incoming queue. Do the work to verify. Mulitcast new blockchain
				data = queue.take(); // Will blocked-wait on empty queue
				System.out.println("Consumer Got Unverified Block: " + data + "\n");
				
				//Do work
				VerifiedBlock = WorkB.Verify(data, this.PID);

				if(VerifiedBlock != null){
					byte[] Signature = Base64.getDecoder().decode(VerifiedBlock.getSignedSHA256());
					boolean verifiedSig = Blockchain.verifySig(VerifiedBlock.getSHA256String().getBytes(), Blockchain.keyPair.getPublic(), Signature);
					
					if(verifiedSig){
					
						VerifiedBlock.setVerificationProcessID(Integer.toString(this.PID));
						//Puzzle solzed
	
						LinkedList <BlockRecord> BC = new LinkedList<BlockRecord>();
						if(Blockchain.blockchain.length() > 0){
							BC = Blockchain.gson.fromJson(Blockchain.blockchain, new TypeToken<LinkedList<BlockRecord>>(){}.getType());
							VerifiedBlock.setPreviousHash(BC.getLast().getSHA256String());
						}
						else{
							VerifiedBlock.setPreviousHash("Head Block");
						}
						
						//Add new block to front of blockchain
						BC.add(VerifiedBlock);
						NewBlockchain = Blockchain.gson.toJson(BC);
					
						for(int i = 0; i < Blockchain.numProcesses; i++){ // send to each process in group, including us:
							sock = new Socket(Blockchain.serverName, Ports.BlockchainServerPortBase + i);
							toServer = new PrintStream(sock.getOutputStream());
	
							//Multicast new Blockchain
							toServer.println(NewBlockchain); 
							toServer.flush();
							sock.close();
						}
					}
				}
				Thread.sleep(1500); //Wait for our blockchain to be updated before processing a new block
			}
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}

class BlockchainWorker extends Thread {
	private Socket sock;
	private int PID;
	
	BlockchainWorker (Socket s, int PID) {
		this.sock = s;
		this.PID = PID;
	}

	public void run(){
		try{
			BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
			String data = "";
			String data2;
			while((data2 = in.readLine()) != null){
				data = data + data2;
			}
			
			System.out.println("Blockchain Server Received Updated Blockchain Ledger.");
			Blockchain.blockchain = data; // Would normally have to check first for winner before replacing.
			
			sock.close();
			
			//if first process, write JSON to disk
			if(this.PID == 0) {
				
				// Write the JSON object to a file:
				try (FileWriter writer = new FileWriter("BlockchainLedger.json")) {
					Blockchain.gson.toJson(data, writer);
					System.out.println("Blockchain Ledger Written to Disk.\n");
				} 
				catch (IOException e) {
					e.printStackTrace();
				}
			}
		} 
		catch (IOException x){
			x.printStackTrace();
		}
	}
}

class BlockchainServer implements Runnable {
	private int PID;
	
	BlockchainServer(int PID) {
		this.PID = PID;
	}
	
	public void run(){
		
		Socket sock;
		System.out.println("Starting the blockchain server input thread using " + Ports.BlockchainServerPort);
		try{
			ServerSocket servsock = new ServerSocket(Ports.BlockchainServerPort, Blockchain.q_len);
			while (true) {
				sock = servsock.accept();
				new BlockchainWorker (sock, this.PID).start();
			}
		}
		catch (IOException ioe) {
			System.out.println(ioe);
		}
	}
}

// Main
public class Blockchain {

	protected static final int q_len = 6;
	protected static String serverName = "localhost";
	protected static String blockchain = "";
	protected static final int numProcesses = 3; // Set this to match your batch execution file that starts N processes with args 0,1,2,...N
	protected static int PID;
	protected static KeyPair keyPair;
	protected static final Map<Integer, String> PublicKeys = new HashMap<>();;
	protected static Gson gson;
	
	//Multicast to each process
	private void MultiSend(){
		try{
			//-------MultiCast Keys----------
			System.out.println("BlockFramework multicasting process key to public key servers.\n\n");
			
			String temp = Integer.toString(PID) + "\n" + keyPair.getPublic().toString();
			Multicast(Ports.KeyServerPortBase, temp);

			Thread.sleep(1000); // wait for keys to settle, normally would wait for an ack

			//-------MultiCast UV Blocks----------
			LinkedList<String> JsonRecord = BlockInput.GetJsonListString(PID);
			Iterator<String> iterator = JsonRecord.iterator();
			String current;
			while(iterator.hasNext()){
				current = iterator.next();
				current = current.replace("\n", "--linebreak--");
				Multicast(Ports.UnverifiedBlockServerPortBase, "PID: " + Blockchain.PID + current);
			}
		} 
		catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	private static KeyPair generateKeyPair(long seed) throws Exception {
		
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
		rng.setSeed(seed);
		keyGenerator.initialize(1024, rng);
    
		return (keyGenerator.generateKeyPair());
	}
	protected static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initVerify(key);
		signer.update(data);
    
		return (signer.verify(sig));
	}
	private static void Multicast(int port, String output) throws IOException {
		Socket sock;
		PrintStream toServer;
		for(int i=0; i< numProcesses; i++){// Send a sample unverified block to each server
			sock = new Socket(serverName, port + i);
			toServer = new PrintStream(sock.getOutputStream());
			toServer.println(output);
			toServer.flush();
			sock.close();
		}
	}

	public static void main(String args[]){

		PID = (args.length < 1) ? 0 : Integer.parseInt(args[0]); // Process ID
		System.out.println("---Andrew's BlockFramework---\n control-c to quit,\n'C' to display verified blocks per process,\n'L' to list Blockchain\n");
		System.out.println("Using processID " + PID + "\n");

		final BlockingQueue<BlockRecord> queue = new PriorityBlockingQueue<>(); // Concurrent queue for unverified blocks
		
		gson = new GsonBuilder().setPrettyPrinting().create();
		
		//------init ports------
		new Ports().setPorts();
		
		//-------init keys-------
		try{
			keyPair = generateKeyPair(999);// Use a random seed in real life
		}catch(Exception e){}
		
		new Thread(new PublicKeyServer()).start();// New thread to process incoming public keys
		new Thread(new UnverifiedBlockServer(queue)).start();// New thread to process incoming unverified blocks
		new Thread(new BlockchainServer(PID)).start();// New thread to process incoming new blockchains
		
		try{
			Thread.sleep(1000);// Wait for servers to start.
		}catch(Exception e){}
		
		new Blockchain().MultiSend();// Multicast some new unverified blocks out to all servers as data
		
		try{
			Thread.sleep(1000);// Wait for multicast to fill incoming queue for our example.
		}catch(Exception e){}

		new Thread(new UnverifiedBlockConsumer(queue, PID)).start();// Start consuming the queued-up unverified blocks
		
		//-----Console Commands-----
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
		char input;
		while(true){
			try{
				input = (char)in.read();
				if(input == 'C'){
					//Print validation credit of each process
					LinkedList <BlockRecord> BC = new LinkedList<BlockRecord>();
					
					BC = gson.fromJson(Blockchain.blockchain, new TypeToken<LinkedList<BlockRecord>>(){}.getType());
					
					BlockRecord temp;
					for(int i = 0; i < numProcesses; i++){
						int numVerifications = 0;
						Iterator<BlockRecord> iterator = BC.iterator();
						while(iterator.hasNext()){
							temp = iterator.next();
							if(temp.getVerificationProcessID().equals(Integer.toString(i))){
								numVerifications++;
							}
						} 
						System.out.println("Process " + i + ": " + numVerifications + " Blocks Verified.\n");
					}
				}
				else if(input == 'L'){
					String tmp = blockchain.replace("}", "\n\n");
					tmp = tmp.replace("{", "");
					tmp = tmp.replace(",", "\n");
					System.out.println(tmp);
				}
			}
			catch(Exception e){}
		}
	}
}




