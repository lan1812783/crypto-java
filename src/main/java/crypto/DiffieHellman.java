package crypto;

import java.security.InvalidAlgorithmParameterException;
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

/** The Diffie-Hellman algorithm. */
public class DiffieHellman {
  private final Logger logger = Logger.getLogger(DiffieHellman.class.getName());
  private static final DiffieHellman instance =
      new DiffieHellman(); // initialized last for its' usage of above static variables

  protected String keyPairGeneratorAlgorithm;
  protected String keyAgreementAlgorithm;
  protected String keyFactoryAlgorithm;

  protected String getKeyPairGeneratorAlgorithm() {
    return "DH";
  }

  protected String getKeyAgreementAlgorithm() {
    return "DH";
  }

  protected String getKeyFactoryAlgorithm() {
    return "DH";
  }

  protected DiffieHellman() {
    keyPairGeneratorAlgorithm = getKeyPairGeneratorAlgorithm();
    keyAgreementAlgorithm = getKeyAgreementAlgorithm();
    keyFactoryAlgorithm = getKeyFactoryAlgorithm();
  }

  public static DiffieHellman getInstance() {
    return instance;
  }

  /**
   * Generates a Diffie-Hellman key pair.
   *
   * @param keySize the size of the generated key pair's public key.
   */
  public KeyPair generateKeyPair(int keySize) {
    try {
      KeyPairGenerator keyPair = KeyPairGenerator.getInstance(keyPairGeneratorAlgorithm);
      keyPair.initialize(keySize);
      return keyPair.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      handleErrors(e);
    }
    return null;
  }

  /**
   * Generates a key pair using parameters from a peer's public key.
   *
   * @param peerPublicKey the peer's public key.
   */
  public KeyPair generateKeyPair(PublicKey peerPublicKey) {
    try {
      DHParameterSpec peerDhParameterSpec = ((DHPublicKey) peerPublicKey).getParams();
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyPairGeneratorAlgorithm);
      keyPairGenerator.initialize(peerDhParameterSpec);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      return keyPair;
    } catch (ClassCastException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      handleErrors(e);
    }
    return null;
  }

  /**
   * Initializes a key agreement from a key pair.
   *
   * @param keyPair the key pair.
   */
  public KeyAgreement getKeyAgreement(KeyPair keyPair) {
    try {
      KeyAgreement keyAgreement = KeyAgreement.getInstance(keyAgreementAlgorithm);
      keyAgreement.init(keyPair.getPrivate());
      return keyAgreement;
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      handleErrors(e);
    }
    return null;
  }

  /**
   * Parses peer's raw public key into an internal public key representation.
   *
   * @param peerData the peer's raw public key.
   */
  public PublicKey getPeerPublicKey(byte[] peerData) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm);
      X509EncodedKeySpec peerX509EncodedKeySpec = new X509EncodedKeySpec(peerData);
      PublicKey peerPublicKey = keyFactory.generatePublic(peerX509EncodedKeySpec);
      return peerPublicKey;
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      handleErrors(e);
    }
    return null;
  }

  /**
   * Verifies peer's public key using a key agreement.
   *
   * @param keyAgreement the key agreement used to verify the peer's public key.
   * @param peerPublicKey the peer's public key to verify.
   */
  public boolean doPhase(KeyAgreement keyAgreement, PublicKey peerPublicKey) {
    try {
      keyAgreement.doPhase(peerPublicKey, true);
      return true;
    } catch (InvalidKeyException | IllegalStateException e) {
      handleErrors(e);
    }
    return false;
  }

  protected void handleErrors(Exception e) {
    logger.log(Level.SEVERE, e.getMessage(), e);
  }
}
