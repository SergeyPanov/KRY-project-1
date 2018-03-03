import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class BobServer {


    private int port;


    public void startCommunicate() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException, InvalidKeyException {

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



        dos.close();
        dis.close();
        out.close();
        in.close();
        socket.close();
        serverSocket.close();


    }

    public void setPort(int port) {
        this.port = port;
    }

}
