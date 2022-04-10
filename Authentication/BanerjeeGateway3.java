import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.SecretKey;

public class BanerjeeGateway3 {

	public static double acosh(double x) {
		return Math.log(x + Math.sqrt(x * x - 1.0));
	}

	public static double chebyshev(double x, int z, int n) {
		return Math.cosh(n * acosh(x) % z);
	}

	public static String XOREncode(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < key.length(); i++)
			sb.append((char) (st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		str = str + st.substring(key.length());
		// System.out.println(st.substring(key.length()));
		return str;
	}

	public static String XORDecodekey(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < key.length(); i++)
			sb.append((char) (st.charAt(i) ^ key.charAt(i)));
		String str = sb.toString();
		return str;
	}

	public static String XORDecodeString(String st, String key) {
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < key.length(); i++)
			sb.append((char) (st.charAt(i) ^ key.charAt(i)));
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

	public static void main(String[] args) throws IOException {
		
		final int PORT = 4086;
		int GWNP_Ui = 4321;
        int Sk_GWN = 4444;
        int GWNP_Sj = 6543;
        
		ServerSocket serverSocket = new ServerSocket(PORT);
		Socket clientSocket = serverSocket.accept();
		DataInputStream din = new DataInputStream(clientSocket.getInputStream());
		DataOutputStream dout = new DataOutputStream(clientSocket.getOutputStream());
		
		String input = "", str2 = "";
		while (!input.equals("stop")) {
			
			String Pj = new Scanner(new File("GWmem.txt")).useDelimiter("\\Z").next();
    		System.out.println("Pj: "+Pj);
			
			////////////////receives from trusted device //////////////////////
			input = din.readUTF(); //SIDj+"<-->"+MIDi+"<-->"+M1+"<-->"+M2+"<-->"+M3+"<-->"+M4;
			System.out.println("Received at GW: "+ input);

			if (input.equalsIgnoreCase("stop")) {
				break;
			}
			else {
				
					String received_user[] = input.split("<-->");
					String SIDj = received_user[0];
					String MIDi = received_user[1];
					String M1 = received_user[2].trim();
					String M2 = received_user[3].trim();
					String M3 = received_user[4].trim();
					String M4 = received_user[5].trim();
					
					String Xi = getSha256(MIDi+Sk_GWN);
					String r1 = XORDecodekey(M2, Xi).trim();
					String r2 = XORDecodekey(M3, Pj).trim();
					String M1p = getSha256(Xi+GWNP_Ui+r1);
				
					 if(!M1p.equals(M1)) { 
						 System.out.println("Something Wrong in M1...."); 
						 break;
					 } 
					 String M4p = getSha256(GWNP_Sj+M2+r2); 
					 if(!M4p.equals(M4)) {
						 System.out.println("Something Wrong in M4...."); 
						 break; 
					 }
					 
					 Random rnd = new SecureRandom();
						int r3 = BigInteger.probablePrime(15, rnd).intValue();
					String M51 = getSha256(GWNP_Sj+r2);
					String M5 = XOREncode(M51, ""+r3);
					String M6 = getSha256(Xi+GWNP_Sj+r1+r2+r3);
					String P1 = XOREncode(Pj, r1);
					String P21 = getSha256(r1+Pj+r2);
					String P2 = XOREncode(P21, Xi);
					
					String sendToDevice = M5 + "<-->" + M6 + "<-->" + P1 + "<-->" + P2 + "<-->"+ Xi;
					
					
					//String xc = XORDecodekey(P1, Pj);
					//System.out.println("xc: " + xc);
					
					System.out.println("MIDi: "+ MIDi);
					System.out.println("Xi: "+ Xi);
					System.out.println("r1: "+ r1);
					System.out.println("r2: "+ r2);
					System.out.println("r3: "+ r3);
					System.out.println("M1: " + M1);
					System.out.println("M1p: " + M1p);
					System.out.println("P1: " + P1);
					
					
				////////////////sending to trusted device //////////////////////					
					dout.writeUTF(sendToDevice); // send to trusted device
					dout.flush();
					System.out.println("Sent to Device from Gateway: "+ sendToDevice);

			}
					
		}
		
	}

}
