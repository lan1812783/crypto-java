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

public class DH {
  private final Logger logger = Logger.getLogger(DH.class.getName());
  private static final DH instance = new DH(); // initialized last for its' usage of above static variables

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

  protected DH() {
    keyPairGeneratorAlgorithm = getKeyPairGeneratorAlgorithm();
    keyAgreementAlgorithm = getKeyAgreementAlgorithm();
    keyFactoryAlgorithm = getKeyFactoryAlgorithm();
  }

  public static DH getInstance() {
    return instance;
  }

  public KeyPair generateKeyPair(int keySize) {
    try {
      KeyPairGenerator keyPair = KeyPairGenerator.getInstance(
          keyPairGeneratorAlgorithm);
      keyPair.initialize(keySize);
      return keyPair.generateKeyPair();
    } catch (NoSuchAlgorithmException e) {
      handleErrors(e);
    }
    return null;
  }

  public KeyPair generateKeyPair(PublicKey peerPublicKey) {
    try {
      DHParameterSpec peerDhParameterSpec = ((DHPublicKey)peerPublicKey)
          .getParams();
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
          keyPairGeneratorAlgorithm);
      keyPairGenerator.initialize(peerDhParameterSpec);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      return keyPair;
    } catch (ClassCastException | NoSuchAlgorithmException |
        InvalidAlgorithmParameterException e) {
      handleErrors(e);
    }
    return null;
  }

  public KeyAgreement getKeyAgreement(KeyPair keyPair) {
    try {
       KeyAgreement keyAgreement = KeyAgreement.getInstance(
           keyAgreementAlgorithm);
       keyAgreement.init(keyPair.getPrivate());
       return keyAgreement;
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      handleErrors(e);
    }
    return null;
  }

  public PublicKey getPeerPublicKey(byte[] peerData) {
    try {
      KeyFactory keyFactory = KeyFactory.getInstance(keyFactoryAlgorithm);
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

  public boolean doPhase(KeyAgreement keyAgreement,
      PublicKey peerPublicKey) {
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
