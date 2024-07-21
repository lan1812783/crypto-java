package crypto;

import io.grpc.Status;

/** Cryptographic definitions. */
public class CryptoDef {
  /** Cryptographic statuses. */
  public class CryptoStatus {
    public static final Status INVALID_ARGUMENT =
        Status.INVALID_ARGUMENT.withDescription("Invalid argument");
  }
}
