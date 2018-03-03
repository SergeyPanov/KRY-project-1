import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class BobServer {


    private int port;


    public void startCommunicate() throws Exception {

        while (true){

            ServerSocket serverSocket = null;

            serverSocket = new ServerSocket(port); // Bob is going to listen on the "port"


            Socket socket = null;
            InputStream in = null;
            OutputStream out = null;

            socket = serverSocket.accept(); // Get socket
            in = socket.getInputStream();   // Get input stream
            out = socket.getOutputStream(); // Get output stream

            // Create data input and data output streams; just for convenience
            assert in != null;
            assert out != null;
            DataInputStream dis = new DataInputStream(in);
            DataOutputStream dos = new DataOutputStream(out);


            // Receive alicePubKeyEnc
            int lengthOfAliceKey = dis.readInt();   // Read length of alicePubKey
            byte[] alicePubKeyEnc = new byte[lengthOfAliceKey];
            dis.readFully(alicePubKeyEnc);  // Read alicePubKeyEnc

            /*
             * Bob has received Alice's public key
             * in encoded format.
             * He instantiates a DH public key from the encoded key material.
             */
            KeyFactory bobKeyFac = KeyFactory.getInstance("DH");
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(alicePubKeyEnc);
            PublicKey alicePubKey = bobKeyFac.generatePublic(x509KeySpec);


            /*
             * Bob gets the DH parameters associated with Alice's public key.
             * He must use the same parameters when he generates his own key
             * pair.
             */
            DHParameterSpec dhParamFromAlicePubKey = ((DHPublicKey)alicePubKey).getParams();


            // Bob creates his own DH key pair
            System.out.println("BOB: Generate DH keypair ...");
            KeyPairGenerator bobKpairGen = KeyPairGenerator.getInstance("DH");
            bobKpairGen.initialize(dhParamFromAlicePubKey);
            KeyPair bobKpair = bobKpairGen.generateKeyPair();


            // Bob creates and initializes his DH KeyAgreement object
            System.out.println("BOB: Initialization ...");
            KeyAgreement bobKeyAgree = KeyAgreement.getInstance("DH");
            bobKeyAgree.init(bobKpair.getPrivate());


            // Bob encodes his public key, and sends it over to Alice.
            byte[] bobPubKeyEnc = bobKpair.getPublic().getEncoded();

            // Send bobPubKeyEnc
            dos.writeInt(bobPubKeyEnc.length); // Send length
            dos.write(bobPubKeyEnc, 0, bobPubKeyEnc.length);    // Send bobPubKeyEnc

            /*
             * Bob uses Alice's public key for the first (and only) phase
             * of his version of the DH
             * protocol.
             */
            System.out.println("BOB: Execute PHASE1 ...");
            bobKeyAgree.doPhase(alicePubKey, true);

            byte[] bobSharedSecret;
            bobSharedSecret = bobKeyAgree.generateSecret();
            System.out.println("Bob secret: " +
                    HexPrinter.toHexString(bobSharedSecret));

            /////////////////////// Authorization ///////////////////////

            TrustedCenter tc = new TrustedCenter();

            BigInteger trustedN = tc.generateN();

            System.out.println("Bob n:" +  trustedN);
            dos.writeUTF(trustedN.toString());  // Send n = p*q
            dos.writeInt(tc.getK());    // Send k
            dos.writeInt(tc.getT());    // Send amount of rounds t


            List<BigInteger> randomInts = new ArrayList<>();    // s1,s2...sk
            BitSet randomBits = new BitSet(tc.getK());  // b1,b2...bk
            List<BigInteger> listV = new ArrayList<>(); // v1,v2...vk

            for (int i = 0; i < tc.getK(); ++i){
                String v;
                try{
                    v = dis.readUTF();
                }catch (EOFException e){
                    break;
                }
                listV.add(new BigInteger(v));
                System.out.println(v);
            }

            Random rand = new Random(); // Need for generation random ints

//            for (int i = 0; i < tc.getK(); i++) {
//                randomInts.add(BigInteger.valueOf((rand.nextInt(Integer.MAX_VALUE) + 1)).mod(trustedN));
//                randomBits.set(i, rand.nextBoolean());
//
//                BigInteger minus1pow = (((new BigInteger("-1")).pow(randomBits.get(i) ? 1 : 0)).mod(trustedN));
//                BigInteger randomIntPow = (randomInts.get(i).pow(2)).modInverse(trustedN);
//
//                listV.add((minus1pow.multiply(randomIntPow)).mod(trustedN));
//            }

            ///////////////// Rounds ////////////////////////////

            BigInteger x = new BigInteger(dis.readUTF());   // Received x value

            System.out.println("Bob x: " + x.toString());

            StringBuilder eBits = new StringBuilder();   // Bit vector (e1, e2...ek)
            for (int i = 0; i < tc.getK(); i++) {
                eBits.append(rand.nextBoolean() ? "1" : "0");
            }

            System.out.println("Bob eBits: " + eBits.toString());
            dos.writeUTF(eBits.toString()); // Send vector (e1,e2...ek) as string

            BigInteger y = new BigInteger(dis.readUTF());   // Receive y

            System.out.println("Bob y: " + y.toString());

            BigInteger totalMultV = new BigInteger("1");

            for (int i = 0; i < tc.getK(); i++) {
                totalMultV = totalMultV
                        .multiply(listV.get(i).pow(eBits.charAt(i) == '1' ? 1 : 0));
            }

            totalMultV = totalMultV.mod(trustedN);
            BigInteger z = (y.pow(2).mod(trustedN)).multiply(totalMultV).mod(trustedN);

            System.out.println("Bob z: " + z.toString());


            /////////////////////// Communication ///////////////////////

//            AES.setKeyValue(Arrays.copyOfRange(bobSharedSecret, 0, 32));
//
//            while (true){
//                String msg;
//                try{
//                    msg = dis.readUTF();
//                }catch (EOFException e){
//                    break;
//                }
//
//                String decrypted = AES.decrypt(msg);
//                String sha256 = SHA.hash256(decrypted);
//                System.out.println("Encoded message: " + msg);
//                System.out.println( "Decoded message: " + decrypted);
//                System.out.println("SHA256 hash: " + sha256);
//
//                dos.writeUTF(sha256);
//            }

            //////////////////////////////////////////////////////////////////
            dos.close();
            dis.close();
            out.close();
            in.close();
            socket.close();
            serverSocket.close();
        }


    }

    public void setPort(int port) {
        this.port = port;
    }

}
