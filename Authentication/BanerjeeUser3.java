import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.io.Writer;
import java.math.BigInteger;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;


public class BanerjeeUser3 {

	public int Di, PW, Rd, T, PID, PIN;
	public String com1;

	public static double acosh(double x)
	{
		return Math.log(x + Math.sqrt(x*x - 1.0));
	}

	public static double chebyshev(double x, int z, int n) {
		return Math.cosh(n*acosh(x)%z);
	}

	public static String XOREncode(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < key.length(); i++)
			sb.append((char)(st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		str = str + st.substring(key.length());
		//System.out.println(st.substring(key.length()));
		return str;
	}

	public static String XORDecodekey(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < key.length(); i++)
			sb.append((char)(st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		return str;
	}

	public static String XORDecodeString(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for(int i = 0; i < key.length(); i++)
			sb.append((char)(st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		str = str + st.substring(key.length());
		return str;
	}

	public static String getSha256(String str) {
		MessageDigest digest;
		String encoded = null;
		try {
			digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(str.getBytes(StandardCharsets.UTF_8));
			encoded = Base64.getEncoder().encodeToString(hash);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return encoded;
	} 

	public static void main(String[] args) throws Exception {
		
		Instant responseStart = Instant.now();
		Instant responseEnd = Instant.now();
		long handshakeDuration = -1;
		long sendMsgSize = -1, receiveMsgSize = -1;;
		// memory usage before execution
		long beforeUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
		double Eelec = 50.0;
		double Eamp = 0.1;
		double d = 1.0;
		
		
		long count = 0, total = 0, avgElapsedTime = 0, n= 1;
		final String HOST = "127.0.0.1";
		final int PORT = 4085;
		
		 int UIDi = 111;
	     int UPWDi = 12345;
	     String BIOi = "00:00:5e:00:53:af";
		
		String exitStatus= "";
		Socket socket = new Socket(HOST, PORT);
		DataInputStream indata=new DataInputStream(socket.getInputStream());  
		DataOutputStream outdata=new DataOutputStream(socket.getOutputStream());  
		BufferedReader brk=new BufferedReader(new InputStreamReader(System.in)); 
		
		while (count<n) {
			
			
			//exitStatus=brk.readLine();//keyboard input

			if (exitStatus.equalsIgnoreCase("stop")) {
				outdata.writeUTF(exitStatus);
				outdata.flush();
				break;
			}
			
			Instant start = Instant.now(); //time count
			
			////////////////Sending to trusted device //////////////////////
			String content = new Scanner(new File("SC.txt")).useDelimiter("\\Z").next();
    		System.out.println("\n----> "+content);
    		
    		String storeRead[] = content.split("<-->"); //""+MXIPi+"<-->"+Xi+"<-->"+Vi+"<-->"+Ai;
    		//System.out.println("\n----> length: "+recvd.length);
    		String MXIPi = storeRead[0];
    		String Xi = storeRead[1];
    		String Vi = storeRead[2];
    		String Ai = storeRead[3];
    		Random rnd = new SecureRandom();
			int r1 = BigInteger.probablePrime(15, rnd).intValue();
			
    		String Ai1 =  getSha256(""+UIDi+UPWDi);
    		String ri =  XORDecodekey(Ai, Ai1).trim();
    		String imgx = getSha256(ri+BIOi);
    		String MIDi = getSha256(""+UIDi+ri);
			String MPWDi = getSha256(""+UPWDi+ri);
			String MXIPi1 = getSha256(MIDi+MPWDi);
			String GWNP_Ui = XORDecodekey(MXIPi, MXIPi1).trim();
			String Vip = getSha256(GWNP_Ui+imgx);
			if(!Vi.equals(Vip)) {
				System.out.println("Credential mismatch... ");
				break;
			}
			String M1 = getSha256(Xi+GWNP_Ui+r1);
			String M2 = XOREncode(Xi, ""+r1);
			
			String sendsize = MIDi+M1+M2;
			sendMsgSize = sendsize.length()*16;
			
			String sendToDevice = MIDi + "<--> "+ M1 + "<-->" + M2; 
    		System.out.println("ri: "+ ri);
    		System.out.println("MIDi: "+ MIDi);
    		System.out.println("Xi: "+ Xi);
    		System.out.println("r1: "+ r1);
    		
    		responseStart = Instant.now(); // start of response time
    		
			outdata.writeUTF(sendToDevice);
			outdata.flush();
			System.out.println("sendToDevice: "+ sendToDevice);
				
////////////////Receiving from trusted device //////////////////////		
			String input2 = indata.readUTF(); //M7 + "<-->" + M8 + "<-->" + M9;
			
			responseEnd = Instant.now(); // End of response time
			
			System.out.println("Received from D: "+input2);
			
			String received[] = input2.split("<-->");
			String M7 = received[0].trim();
			String M8 = received[1].trim();
			String M9 = received[2].trim();
			String r2 = XORDecodekey(M7, Xi).trim();
			String Pjr3 = XORDecodeString(M8, r2).trim();
			String M9p = getSha256(r1+r2);
			
			String receivesize = received[0]+received[1]+received[2];
			receiveMsgSize = receivesize.length()*16;
			
			if(!M9p.equals(M9)) {
				 System.out.println("Something Wrong in M9...."); 
				 break; 
			 }
			String SK = getSha256(Xi+Pjr3+r2+r1);
			
			System.out.println("r2: "+ r2);
			System.out.println("Pjr3: "+ Pjr3);
			System.out.println("SK: "+ SK +"\n");
			
			Instant finish = Instant.now();
			handshakeDuration = Duration.between(start, finish).toMillis();
			
			
			
			count++;
			outdata.writeUTF("stop");
			outdata.flush();
			
			long afterUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
			long actualMemUsed=afterUsedMem-beforeUsedMem;
			double memKB = Math.round(((afterUsedMem/(8*1024))*100))/100.0 ;
			
			long responseTime = Duration.between(responseStart, responseEnd).toMillis();
			double sendEnergy = (Eelec*sendMsgSize)+(Eamp*sendMsgSize*d*d);
			double receiveEnergy = Eelec*receiveMsgSize;
			double totalEnergy = sendEnergy+receiveEnergy;
			
			System.out.println("\nresponse time: "+responseTime+" milliseconds");
			System.out.println("handshake duration: "+handshakeDuration+" milliseconds");
			System.out.println("memory usage: " + memKB + " KB");
			System.out.println("Communication cost (send message size): " + sendMsgSize + " bytes");
			System.out.println("receive message size: " + receiveMsgSize + " bytes");
			System.out.println("Sending Energy: " + sendEnergy + " nJ");
			System.out.println("Receiving Energy: " + receiveEnergy + " nJ");
			System.out.println("Total Energy: " + totalEnergy + " nJ");
			
			String store = responseTime+"\t"+handshakeDuration+"\t"+memKB+"\t"+sendMsgSize+"\t"+receiveMsgSize+"\t"+sendEnergy+"\t"+receiveEnergy+"\t"+totalEnergy;
			Writer output;
			output = new BufferedWriter(new FileWriter("Results.txt", true));  //clears file every time
			output.append(store+"\n");
			output.close();
		}
	} 

}
