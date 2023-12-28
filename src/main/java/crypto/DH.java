package crypto;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyAgreement;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;

public class DH {
  private static final Logger logger = Logger.getLogger(DH.class.getName());

  private static String dhAlgorithm = "DH";

  public static enum KEY_SIZE {
    DH_KEY_SIZE_1024(1024),
    DH_KEY_SIZE_2048(2048);

    private int size;

    KEY_SIZE(int size) {
      this.size = size;
    }

    public int getSize() {
      return size;
    }
  }

  public static KeyPair dhGenerateKeyPair(KEY_SIZE keySize) {
    try {
      KeyPairGenerator keyPair = KeyPairGenerator.getInstance(dhAlgorithm);
      keyPair.initialize(keySize.getSize());
      return keyPair.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      handleErrors(e);
    }
    return null;
  }

  public static KeyPair dhGenerateKeyPair(PublicKey peerPublicKey) {
    try {
      DHParameterSpec peerDhParameterSpec = ((DHPublicKey)peerPublicKey)
          .getParams();
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
          dhAlgorithm);
      keyPairGenerator.initialize(peerDhParameterSpec);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      return keyPair;
    } catch (Exception e) {
      handleErrors(e);
    }
    return null;
  }

  public static KeyAgreement dhGetKeyAgreement(KeyPair keyPair) {
    try {
       KeyAgreement keyAgreement = KeyAgreement.getInstance(dhAlgorithm);
       keyAgreement.init(keyPair.getPrivate());
       return keyAgreement;
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      handleErrors(e);
    }
    return null;
  }

  public static PublicKey getPeerPublicKey(byte[] peerData) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance(dhAlgorithm);
      X509EncodedKeySpec peerX509EncodedKeySpec = new X509EncodedKeySpec(
          peerData);
      PublicKey peerPublicKey = keyFactory.generatePublic(
          peerX509EncodedKeySpec);
      return peerPublicKey;
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      handleErrors(e);
    }
    return null;
  }

  public static boolean dhDoPhase(KeyAgreement keyAgreement,
      PublicKey peerPublicKey) {
    try {
      keyAgreement.doPhase(peerPublicKey, true);
      return true;
    } catch (InvalidKeyException | IllegalStateException e) {
      handleErrors(e);
    }
    return false;
  }

  private static void handleErrors(Exception e) {
    logger.log(Level.SEVERE, e.getMessage(), e);
  }
}
