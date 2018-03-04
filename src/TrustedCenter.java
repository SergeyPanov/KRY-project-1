import java.math.BigInteger;
import java.util.Random;

public class TrustedCenter {
    private BigInteger p;
    private BigInteger q;

    private BigInteger n;

    private int k = 3;
    public static final int t = 4;

    public BigInteger generateN(){
        /*
        Here is generated 2 int numbers uses 16 bits each.
        16 because of multiplication of unsigned numbers will need max 32 bit.
         */
        p = BigInteger.probablePrime(16, new Random());
        q = BigInteger.probablePrime(16, new Random());

        n = p.multiply(q);

        return n;
    }

    public int getK() {
        return k;
    }

}
