import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

public class Main {

    public static void main(String[] args) throws InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, IOException {
        assert args.length == 1;

        if (args[0].equals("-s")){
            BobServer bob = new BobServer();
            bob.setPort(4444);
            bob.startCommunicate();
        }

        if (args[0].equals("-c") ){
            AliceClient alice = new AliceClient();
            alice.setPort(4444);
            alice.setHost("127.0.0.1");
            alice.startCommunication();
        }


    }
}
