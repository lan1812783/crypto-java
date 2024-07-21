package crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.logging.Logger;

/** The Elliptic-curve Diffie-Hellman algorithm. */
public class EllipticCurveDiffieHellman extends DiffieHellman {
  private static final Logger logger = Logger.getLogger(EllipticCurveDiffieHellman.class.getName());
  private static final EllipticCurveDiffieHellman instance =
      new EllipticCurveDiffieHellman(); // initialized last for
  // its' usage of above
  // static variables

  private String[] supportedCurves;

  @Override
  protected String getKeyPairGeneratorAlgorithm() {
    return "EC";
  }

  @Override
  protected String getKeyAgreementAlgorithm() {
    return "ECDH";
  }

  @Override
  protected String getKeyFactoryAlgorithm() {
    return "EC";
  }

  private EllipticCurveDiffieHellman() {
    super();
    populateSupportedCurves();
  }

  public static EllipticCurveDiffieHellman getInstance() {
    return instance;
  }

  private void populateSupportedCurves() {
    String supportedCurvesAttribute =
        Security.getProviders("AlgorithmParameters.EC")[0]
            .getService("AlgorithmParameters", "EC")
            .getAttribute("SupportedCurves");
    if (supportedCurvesAttribute == null) {
      supportedCurves = new String[0];
      return;
    }
    String[] supportedCurveStrings = supportedCurvesAttribute.split("\\|");
    supportedCurves = new String[supportedCurveStrings.length];
    for (int i = 0; i < supportedCurveStrings.length; i++) {
      String supportedCurveString = supportedCurveStrings[i];
      try {
        supportedCurves[i] = supportedCurveString.substring(1, supportedCurveString.indexOf(","));
      } catch (Exception e) {
        handleErrors(e);
      }
    }
  }

  private boolean isCurveSupported(String curveName) {
    for (int i = 0; i < supportedCurves.length; i++) {
      if (curveName.equals(supportedCurves[i])) {
        return true;
      }
    }
    return false;
  }

  /**
   * Generates a key pair using a supported curve.
   *
   * @param curveName the curve name used to perform the key pair generation
   */
  public KeyPair generateKeyPair(String curveName) {
    if (!isCurveSupported(curveName)) {
      handleErrors(
          new NoSuchAlgorithmException(String.format("Curve %s is not supported", curveName)));
      return null;
    }
    try {
      KeyPairGenerator keyPair = KeyPairGenerator.getInstance(keyPairGeneratorAlgorithm);
      ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(curveName);
      keyPair.initialize(ecGenParameterSpec);
      return keyPair.generateKeyPair();
    } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      handleErrors(e);
    }
    return null;
  }

  @Override
  public KeyPair generateKeyPair(PublicKey peerPublicKey) {
    try {
      ECParameterSpec peerDhParameterSpec = ((ECPublicKey) peerPublicKey).getParams();
      KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyPairGeneratorAlgorithm);
      keyPairGenerator.initialize(peerDhParameterSpec);
      KeyPair keyPair = keyPairGenerator.generateKeyPair();
      return keyPair;
    } catch (ClassCastException | NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
      handleErrors(e);
    }
    return null;
  }
}
