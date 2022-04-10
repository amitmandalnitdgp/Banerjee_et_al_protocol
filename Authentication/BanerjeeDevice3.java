import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Writer;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.SecretKey;

public class BanerjeeDevice3 {

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

		double Eelec = 50.0;
		double Eamp = 0.1;
		double d = 1.0;
		long size1 = -1, size2 = -1, size3 = -1, size4 = -1;
		
		final String HOST = "127.0.0.1";
		final int PORTin = 4085;
		final int PORTout = 4086;
		int SIDj = 2222;
    	int GWNP_Sj = 6543;
/////////////////////// sockets for the new device ///////////////////////////////////////////////////////////////
		ServerSocket trustedServerSocket = new ServerSocket(PORTin);
		Socket trustedClientSocket = trustedServerSocket.accept();
		DataInputStream Device_indata=new DataInputStream(trustedClientSocket.getInputStream());  
		DataOutputStream Device_outdata=new DataOutputStream(trustedClientSocket.getOutputStream());  

/////////////////////// sockets for the Gateway ///////////////////////////////////////////////////////////////		
		
		Socket GWsocket = new Socket(HOST, PORTout);
		DataInputStream GWindata=new DataInputStream(GWsocket.getInputStream());  
		DataOutputStream GWoutdata=new DataOutputStream(GWsocket.getOutputStream()); 
		
///////////////////////////////////////////////////////////////////////////////////////////////////////////////////		
		String input = "", input2 = "";
		while (!input.equals("stop")) {
			
			String Pj = new Scanner(new File("mem.txt")).useDelimiter("\\Z").next();
    		System.out.println("Pj: "+Pj);
    		
			//////////////// receives from User //////////////////////
			input = Device_indata.readUTF(); // MIDi + "<--> "+ M1 + "<-->" + M2
			System.out.println("Received at D from U: "+ input);
			
					
			if (input.equalsIgnoreCase("stop")) {
				GWoutdata.writeUTF(input);
				GWoutdata.flush();
				break;
			}else {
					
				String received_user[] = input.split("<-->");
				String MIDi = received_user[0];
				String M1 = received_user[1];
				String M2 = received_user[2];
				
				size1 =(MIDi.length()+M1.length()+M2.length())*16; // received message size
				
				Random rnd = new SecureRandom();
				int r2 = BigInteger.probablePrime(15, rnd).intValue();
				String M3 = XOREncode(Pj, ""+r2);
				String M4 = getSha256(GWNP_Sj+M2+r2);
				String sendToGW = SIDj+"<-->"+MIDi+"<-->"+M1+"<-->"+M2+"<-->"+M3+"<-->"+M4;
				System.out.println("r2: "+ r2);
				
				String sendtoGWsize = ""+SIDj+MIDi+M1+M2+M3+M4;
				size2 = sendtoGWsize.length()*16;
				
				////////////////Sending to Gateway //////////////////////
				GWoutdata.writeUTF(sendToGW);
				GWoutdata.flush();
				System.out.println("sent to gateway: "+ sendToGW);
				
				////////////////receives from Gateway //////////////////////
				input2 = GWindata.readUTF(); // M5 + "<-->" + M6 + "<-->" + P1 + "<-->" + P2;
				System.out.println("received from GW: "+ input2);
				
				String received_GW[] = input2.split("<-->");
				String M5 = received_GW[0].trim();
				String M6 = received_GW[1].trim();
				String P1 = received_GW[2].trim();
				String P2 = received_GW[3].trim();
				String Xi = received_GW[4].trim();
				
				size3 = (M5.length()+M6.length()+P1.length()+P2.length()+Xi.length())*16;
				
				String r1 = XORDecodekey(P1, Pj).trim();
				String P21 = getSha256(r1+Pj+r2);
				String Xid = XORDecodekey(P21, P2).trim();
				String M51 = getSha256(""+GWNP_Sj+r2); 
				String r3 = XORDecodekey(M5, M51).trim();
				String M6p = getSha256(Xi+GWNP_Sj+r1+r2+r3);
				if(!M6p.equals(M6)) {
					 System.out.println("Something Wrong in M6...."); 
					 break; 
				 }
				
				String SK = getSha256(Xi+Pj+r3+r2+r1);
						
				String M7 = XOREncode(Xi, ""+r2);
				String Pjr3 = Pj+r3;
				String M8 = XOREncode(Pjr3, ""+r2);
				String M9 = getSha256(r1+r2);
				String sendToUser = M7 + "<-->" + M8 + "<-->" + M9;
				
				size4 = (M7.length()+M8.length()+M9.length()); 
				
				System.out.println("P1: " + P1);
				System.out.println("P2: " + P2);
				System.out.println("r1: "+ r1);
				System.out.println("Xi: "+ Xi);
				System.out.println("Xid: "+ Xid);
				System.out.println("r3: "+ r3);
				System.out.println("M6: "+ M6);
				System.out.println("M6p: "+ M6p);
				System.out.println("Pjr3: " + Pjr3);
				
				////////////////Sending to User //////////////////////
				Device_outdata.writeUTF(sendToUser);
				Device_outdata.flush();
				System.out.println("Send from Device to User:" + sendToUser);
				
				System.out.println("SK: "+ SK +"\n");
				
				long receiveMsgSize = size1+size3;
				long sendMsgSize = size2+size4;
				long afterUsedMem=Runtime.getRuntime().totalMemory()-Runtime.getRuntime().freeMemory();
				double memKB = Math.round(((afterUsedMem/(8*1024))*100))/100.0 ;
				double sendEnergy = (Eelec*sendMsgSize)+(Eamp*sendMsgSize*d*d);
				double receiveEnergy = Eelec*receiveMsgSize;
				double totalEnergy = sendEnergy+receiveEnergy;
				
				System.out.println("memory usage: " + memKB + " KB");
				System.out.println("Communication cost (send message size): " + sendMsgSize + " bytes");
				System.out.println("receive message size: " + receiveMsgSize + " bytes");
				System.out.println("Sending Energy: " + sendEnergy + " nJ");
				System.out.println("Receiving Energy: " + receiveEnergy + " nJ");
				System.out.println("Total Energy: " + totalEnergy + " nJ");
				
				String store = memKB+"\t"+sendMsgSize+"\t"+receiveMsgSize+"\t"+sendEnergy+"\t"+receiveEnergy+"\t"+totalEnergy;
				Writer output;
				output = new BufferedWriter(new FileWriter("Results.txt", true));  //clears file every time
				output.append(store+"\n");
				output.close();
				
			}
		}

	}

}
