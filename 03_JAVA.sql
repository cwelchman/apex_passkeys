create or replace and compile java source named ca_sec."ECDSAVerify" as
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

public class ECDSAVerify {

    public static int verify(byte[] pubX, byte[] pubY,
                             byte[] signature, byte[] data) {
        try {
            // Build the EC public key from raw X/Y coordinates
            BigInteger x = new BigInteger(1, pubX);
            BigInteger y = new BigInteger(1, pubY);

            AlgorithmParameters params =
                AlgorithmParameters.getInstance("EC");
            params.init(new ECGenParameterSpec("secp256r1"));
            ECParameterSpec ecSpec =
                params.getParameterSpec(ECParameterSpec.class);

            ECPoint point = new ECPoint(x, y);
            ECPublicKeySpec keySpec = new ECPublicKeySpec(point, ecSpec);

            KeyFactory kf = KeyFactory.getInstance("EC");
            PublicKey publicKey = kf.generatePublic(keySpec);

            // Verify the signature
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(publicKey);
            sig.update(data);

            return sig.verify(signature) ? 1 : 0;
        } catch (Exception e) {
            // Any failure (bad key, bad signature format, etc.) => invalid
            return 0;
        }
    }
}
/
