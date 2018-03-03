import javax.crypto.KeyAgreement;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class AliceClient {

    private int port = 4444;
    private String host;
    private int keySize = 512;

    public void startCommunication() throws Exception {

        // Create socket for communication
        Socket socket = null;
        socket = new Socket(host, port);

        // Create input and output streams
        OutputStream socketOutputStream = socket.getOutputStream();
        InputStream socketInputStream = socket.getInputStream();

        // Create data input and data output streams; just for convenience
        DataOutputStream dos = new DataOutputStream(socketOutputStream);
        DataInputStream dis = new DataInputStream(socketInputStream);

        /*
         * Alice creates her own DH key pair with 512-bit key size
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
        byte[] aliceSharedSecret;
        aliceSharedSecret = aliceKeyAgree.generateSecret();


        System.out.println("Alice secret: " +
                HexPrinter.toHexString(aliceSharedSecret));


        /////////////////////// Communication phase ///////////////////////

        AES.setKeyValue(Arrays.copyOfRange(aliceSharedSecret, 0, 32));

        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));

        while (true){
            System.out.print("client: ");
            String userInput = stdIn.readLine();
            if ("q".equals(userInput)){
                break;
            }
            String encodedMsg = AES.encrypt(userInput);
            System.out.println("Encoded: " + encodedMsg);
            dos.writeUTF(AES.encrypt(userInput));
        }


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
