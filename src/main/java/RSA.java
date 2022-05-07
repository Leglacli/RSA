import java.math.BigInteger;
import java.util.Random;
import java.util.Scanner;

public class RSA {

    public static boolean MillerRabinTest(BigInteger n, Random r) {

        BigInteger temp = BigInteger.ZERO;

        do {
            temp = new BigInteger(n.bitLength()-1, r);
        } while (temp.compareTo(BigInteger.ONE) <= 0);
        if (!n.gcd(temp).equals(BigInteger.ONE))
            return false;

        BigInteger base = n.subtract(BigInteger.ONE);
        BigInteger TWO = new BigInteger("2");
        int k=0;
        while ( (base.mod(TWO)).equals(BigInteger.ZERO)) {
            base = base.divide(TWO);
            k++;
        }

        BigInteger curValue = modPow(temp,base,n);
        if (curValue.equals(BigInteger.ONE) || curValue.equals(n.subtract(BigInteger.ONE)))
            return true;
        for (int i=0; i<k; i++) {
            if (curValue.equals(n.subtract(BigInteger.ONE)))
                return true;
            else
                curValue = modPow(curValue,TWO,n);
        }
        return false;
    }
    public static boolean MillerRabin(BigInteger n) {

        int numTimes = 20;
        Random r = new Random();

        for (int i=0; i<numTimes; i++)
            if (!MillerRabinTest(n,r))
                return false;
        return true;
    }

    public static BigInteger modPow(BigInteger a, BigInteger e, BigInteger m){

        BigInteger result = BigInteger.ONE;
        BigInteger apow=a;

        for (int idx = 0; idx < e.bitLength(); ++idx) {
            if (e.testBit(idx)) {
                result = result.multiply(apow).mod(m);
            }
            apow = apow.multiply(apow).mod(m);
        }
        return result;
    }

    public static BigInteger modInverse(BigInteger a, BigInteger m) {
        BigInteger m0 = m;
        BigInteger x = BigInteger.ONE;
        BigInteger y = BigInteger.ZERO;
        BigInteger q, b;

        if (m.equals(BigInteger.ONE))
            return BigInteger.ZERO;

        while(a.compareTo(BigInteger.ONE) == 1) {
            q = a.divide(m);
            b = m;
            m = a.mod(m);
            a = b;
            b = y;
            y = x.subtract(q.multiply(y));
            x = b;
        }
        if (x.compareTo(BigInteger.ZERO) == -1)
            x = x.add(m0);
        return x;
    }

    public static BigInteger encryptMessage(BigInteger p, BigInteger q, BigInteger m) {

        BigInteger n = p.multiply(q);
        BigInteger fiOfn = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        Scanner scanner1 = new Scanner(System.in);
        System.out.println("Enter an 'e' number between 1 and " + fiOfn + " and 'e' and " + fiOfn + " are relatively prime: ");
        BigInteger e = scanner1.nextBigInteger();

        while(!e.gcd(fiOfn).equals(BigInteger.ONE) || e.compareTo(BigInteger.ONE) == 0 || e.compareTo(fiOfn) == 1) {
            System.out.println("Wrong value, try again!");
            e = scanner1.nextBigInteger();
            if (e.gcd(fiOfn).equals(BigInteger.ONE) && e.compareTo(BigInteger.ONE) == 1 && e.compareTo(fiOfn) == -1)
                break;
        }

        BigInteger d = modInverse(e, fiOfn);
        System.out.println("Public key: (" + e + "," + n + ")");
        System.out.println("Private key: " + d);

        return modPow(m,e,n);
    }

    public static BigInteger[] euclideanAlgorithm(BigInteger a, BigInteger b) {
        BigInteger n = BigInteger.ONE;
        BigInteger r, q, x, y;
        BigInteger x0 = BigInteger.ONE;
        BigInteger x1 = BigInteger.ZERO;
        BigInteger y0 = BigInteger.ZERO;
        BigInteger y1 = BigInteger.ONE;

        while (!b.equals(BigInteger.ZERO)) {
            r = a.mod(b);
            q = a.divide(b);
            a = b;
            b = r;

            x = x1;
            y = y1;
            x1 = q.multiply(x1).add(x0);
            y1 = q.multiply(y1).add(y0);
            x0 = x;
            y0 = y;

            n = n.multiply(BigInteger.valueOf(-1));
        }

        x = n.multiply(x0);
        y = n.multiply(BigInteger.valueOf(-1)).multiply(y0);

        return new BigInteger[]{a, b, x, y};
    }

    public static BigInteger simpleDecryptMessage(BigInteger p, BigInteger q, BigInteger d, BigInteger c) {
        BigInteger n = p.multiply(q);
        return modPow(c, d, n);
    }

    public static BigInteger decryptMessage(BigInteger p, BigInteger q, BigInteger d, BigInteger c) {
        //c1 = c^(d mod p -1) mod p
        //c2 = c^(d mod q -1) mod q

        BigInteger dp = d.mod(p.subtract(BigInteger.ONE));
        BigInteger dq = d.mod(q.subtract(BigInteger.ONE));

        BigInteger c1 = modPow(c, dp, p);
        BigInteger c2 = modPow(c, dq, q);

        //message = c1*x*M1 + c2*y*M2 mod M
        // M1 = q, M2 = p
        BigInteger M = p.multiply(q);
        BigInteger x = euclideanAlgorithm(p,q)[3];
        BigInteger y = euclideanAlgorithm(p,q)[2];

        return c1.multiply(x).multiply(q).add(c2.multiply(y).multiply(p)).mod(M);
    }

    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);

        //First prime
        System.out.println("Enter a prime number:");
        BigInteger p = scanner.nextBigInteger();
        while (!MillerRabin(p)) {
            System.out.println("The number entered is not a prime, enter a new one: ");
            p = scanner.nextBigInteger();
            if (MillerRabin(p))
                break;
        }

        //Second prime
        System.out.print("Enter the next prime number: ");
        BigInteger q = scanner.nextBigInteger();
        while (!MillerRabin(q)) {
            System.out.println("The number entered is not a prime, enter a new one:");
            q = scanner.nextBigInteger();
            if (MillerRabin(q))
                break;
        }

        //Getting the message and encrypting it
        System.out.println("Enter a message to encrypt: ");
        BigInteger t = scanner.nextBigInteger();
        System.out.println("Encrypted message: " + encryptMessage(p, q, t));

        //Decrypting a message
        System.out.println("Enter a message to decrypt it: ");
        BigInteger c = scanner.nextBigInteger();
        System.out.println("Enter the private key: ");
        BigInteger d = scanner.nextBigInteger();

        System.out.println("Decrypted message using simpleDecryptMessage: " + simpleDecryptMessage(p, q, d, c));

        System.out.println("Decrypted message: " + decryptMessage(p, q, d, c));
    }
}
