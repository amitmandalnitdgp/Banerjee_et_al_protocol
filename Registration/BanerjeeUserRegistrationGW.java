import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.io.*;
import java.math.BigInteger;  

class BanerjeeUserRegistrationGW{  
	
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
	
	
	public static void main(String args[])throws Exception{  
        final int PORT = 4082;
        int GWNP_Ui = 4321;
        int Sk_GWN = 4444;
        int GWNP_Sj = 6543;
        ServerSocket serverSocket = new ServerSocket(PORT);
        Socket clientSocket = serverSocket.accept();
        DataInputStream din=new DataInputStream(clientSocket.getInputStream());  
		DataOutputStream dout=new DataOutputStream(clientSocket.getOutputStream());  
		
		String input="",str2="";  
		while(!input.equals("stop")){  
			
			input=din.readUTF(); // receive option
			System.out.println("input: "+input);
			
			if (input.equalsIgnoreCase("stop")) {
            	serverSocket.close();
            	System.out.println("---->>> connection aborted.......");
                break;
            } 
//////////////////////////////////User Registration /////////////////////////////////			
			else if (input.equals("u")){
				input=din.readUTF(); // receive data
            	String received[] = input.split("<-->"); // Mpi, IDi
    			String MIDi = received[0];
    			String MPWDi = received[1];
    			String MXIPi1 = getSha256(MIDi+MPWDi);
    			String MXIPi = XOREncode(MXIPi1, ""+GWNP_Ui);
    			String Xi = getSha256(MIDi+Sk_GWN);
    			
            	dout.writeUTF(MXIPi+"<-->"+Xi); //send
				dout.flush();	
				System.out.println("user registration completed.");
            } 
//////////////////////////////////Sensor Registration /////////////////////////////////			
			else if(input.equals("s")) {
				input=din.readUTF(); // receive data
				
            	String received[] = input.split("<-->"); // 0-SIDj - 1-MPj - 2-MNj - 3-T1
            	String SIDj = received[0];
            	String MXj = received[1];
            	String MYj = received[2];
            	String rj = XORDecodeString(MYj, ""+ GWNP_Sj).trim();
            	System.out.println("rj: "+rj);
            	
            	String MXjp = getSha256(SIDj+rj+GWNP_Sj);
            	if(!MXjp.equals(MXj)) {
            		System.out.println("Error on credentil matching... MXj Mismatch...");
            		break;
            	}
            	String Pj = getSha256(MXj+Sk_GWN);
            	          	
            	dout.writeUTF(Pj); //send
				dout.flush();
				
				Writer output;
	    		output = new BufferedWriter(new FileWriter("GWmem.txt"));  //clears file every time
	    		output.append(Pj);
	    		output.close();
				System.out.println("Sensor registration completed.");
            	
            } else {
            	System.out.println("type 'u' for user registration then hit enter");
            	System.out.println("type 's' for sensor registration then hit enter");
            }
		}
		din.close();  
		clientSocket.close();  
		serverSocket.close();

	}
}  