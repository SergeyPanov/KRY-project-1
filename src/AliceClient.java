import javax.crypto.KeyAgreement;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

public class AliceClient {

    private int port = 4444;
    private String host;
    private int keySize = 512;
    private Socket socket = null;
    private OutputStream socketOutputStream = null;
    private InputStream socketInputStream = null;
    private DataOutputStream dos = null;
    private DataInputStream dis = null;
    byte[] aliceSharedSecret;
    private BigInteger trustedN;
    private int k;
    private int t;

    List<BigInteger> randomInts = new ArrayList<>();    // s1,s2...sk
    BitSet randomBits;  // b1,b2...bk
    List<BigInteger> listV = new ArrayList<>(); // v1,v2...vk
    Random rand = new Random(); // Need for generation random ints
    private void agreeAboutKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {

        /*
         * Alice creates her own DH key pair with keySize key size
         */
        System.out.println("ALICE: Generate DH keypair ...");
        KeyPairGenerator aliceKpairGen = null;
        try {
            aliceKpairGen = KeyPairGenerator.getInstance("DH");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        assert aliceKpairGen != null;
        aliceKpairGen.initialize(keySize);
        KeyPair aliceKpair = aliceKpairGen.generateKeyPair();

        // Alice creates and initializes her DH KeyAgreement object
        System.out.println("ALICE: Initialization ...");
        KeyAgreement aliceKeyAgree = null;
        try {
            aliceKeyAgree = KeyAgreement.getInstance("DH");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            assert aliceKeyAgree != null;
            aliceKeyAgree.init(aliceKpair.getPrivate());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        // Alice encodes her public key, and sends it over to Bob.
        byte[] alicePubKeyEnc = aliceKpair.getPublic().getEncoded();

        // Send length and alicePubKeyEnc
        dos.writeInt(alicePubKeyEnc.length);   // Send length of alicePubKey
        dos.write(alicePubKeyEnc, 0, alicePubKeyEnc.length);    // Send alicePubKeyEnc


        // Receive bobPubKeyEnc
        int lengthOfBobKey = -1;
        lengthOfBobKey = dis.readInt();   // Read length of bobPubKeyEnc
        byte[] bobPubKeyEnc = new byte[lengthOfBobKey];
        dis.readFully(bobPubKeyEnc);  // Read bobPubKeyEnc

        /*
         * Alice uses Bob's public key for the first (and only) phase
         * of her version of the DH
         * protocol.
         * Before she can do so, she has to instantiate a DH public key
         * from Bob's encoded key material.
         */
        KeyFactory aliceKeyFac = KeyFactory.getInstance("DH");
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(bobPubKeyEnc);
        PublicKey bobPubKey = aliceKeyFac.generatePublic(x509KeySpec);
        System.out.println("ALICE: Execute PHASE1 ...");
        aliceKeyAgree.doPhase(bobPubKey, true);


        /*
         * At this stage, both Alice and Bob have completed the DH key
         * agreement protocol.
         * Both generate the (same) shared secret.
         */
        aliceSharedSecret = aliceKeyAgree.generateSecret();

        System.out.println("Alice secret: " +
                HexPrinter.toHexString(aliceSharedSecret));
    }


    private void communicate() throws Exception {
        AES.setKeyValue(Arrays.copyOfRange(aliceSharedSecret, 0, 32));

        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

        while (true){
            System.out.print("client: ");
            String userInput = stdIn.readLine();
            if ("q".equals(userInput)){
                break;
            }
            String encodedMsg = AES.encrypt(userInput);
            String sha256 = SHA.hash256(userInput);
            System.out.println("Encoded: " + encodedMsg);
            System.out.println("SHA256: " + sha256);
            dos.writeUTF(encodedMsg);

            String receivedSha256 = dis.readUTF();
            if (receivedSha256.equals(sha256)){
                System.out.println("Message was not changed");
            }else {
                System.out.println("Message was changed");
            }
        }

    }

    private void identifyMyself() throws IOException {
        trustedN = new BigInteger(dis.readUTF());    // Receive n = p*q
        k = dis.readInt();  // Receive k
        t = dis.readInt();  // Receive amount of rounds t
        System.out.println("Alice n:" +  trustedN);
        System.out.println("Alice k:" +  k);

        randomInts = new ArrayList<>();    // s1,s2...sk
        randomBits = new BitSet(k);  // b1,b2...bk
        listV = new ArrayList<>(); // v1,v2...vk

        /*
        Choose k positive numbers less than trustedN.
        Choose k bits 0 or 1
         */
        System.out.print("Serets: ");
        for (int i = 0; i < k; i++) {
            BigInteger si = new BigInteger(trustedN.bitLength() + 1, rand).mod(trustedN);

            while (si.gcd(trustedN).intValue() != 1){
                si = new BigInteger(trustedN.bitLength() + 1, rand).mod(trustedN);
            }
            randomInts.add(si);
            randomBits.set(i, rand.nextBoolean());

            BigInteger minus1pow = (((new BigInteger("-1")).pow(randomBits.get(i) ? 1 : 0)));
            BigInteger vi = minus1pow.multiply(randomInts.get(i).pow(2)).modInverse(trustedN);

            listV.add(vi);
        }

        System.out.println("\nAlice vi: ");
        // Send public vi vector
        for (BigInteger bi:
                listV) {
            System.out.println(bi.toString());
            dos.writeUTF(bi.toString());
        }

    }

    private void playRounds() throws IOException {
        for (int j = 0; j < t; j++) {

                    /*
        Count x value like x = (-1)^b * r^2
         */
            BigInteger randomR = new BigInteger(trustedN.bitLength() + 1, rand).mod(trustedN);   // Randomly selected r
            int bitIndex = (int) (Math.random() * (randomBits.length()));   // Randomly selected bitIndex

            System.out.println("Alice r: " + randomR.toString());
            System.out.println("Alice bitIbdex: " + bitIndex);

            BigInteger x = (((new BigInteger("-1")).pow(randomBits.get(bitIndex) ? 1 : 0))
                    .multiply((randomR.pow(2))))
                    .mod(trustedN);


            System.out.println("Alice x: " + x.toString());

            dos.writeUTF(x.toString());

            String eBits = dis.readUTF();

            System.out.println("Alice eBits: " + eBits);


            BigInteger totalMultS = new BigInteger("1");
            for (int i = 0; i < k; i++) {
                totalMultS = totalMultS
                        .multiply(randomInts.get(i).pow(eBits.charAt(i) == '1' ? 1 : 0));
            }

            BigInteger y = totalMultS.multiply(randomR.mod(trustedN)).mod(trustedN);


            dos.writeUTF(y.toString()); // Send y
            System.out.println("Alice y: " + y.toString());

        }

    }

    public void startCommunication() throws Exception {

        /*
        Setup connection with server.
         */

        // Create socket for communication.
        socket = new Socket(host, port);

        // Create input and output streams.
        socketOutputStream = socket.getOutputStream();
        socketInputStream = socket.getInputStream();

        // Create data input and data output streams; just for convenience.
        dos = new DataOutputStream(socketOutputStream);
        dis = new DataInputStream(socketInputStream);


        /////////////////////// Key agreement ///////////////////////
        agreeAboutKey();

        /////////////////////// Identification ///////////////////////

        identifyMyself();


        ///////////////// Rounds ////////////////////////////

        playRounds();

        /////////////////////// Communication ///////////////////////
        communicate();

        // Close opened streams.
        dis.close();
        dos.close();
        socketOutputStream.close();
        socketInputStream.close();
        socket.close();

    }


    public void setHost(String host) {
        this.host = host;
    }

    public void setPort(int port) {
        this.port = port;
    }


    public void setKeySize(int keySize) {
        this.keySize = keySize;
    }
}
