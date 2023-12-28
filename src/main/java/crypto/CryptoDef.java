package crypto;

import io.grpc.Status;

public class CryptoDef {
  public class CryptoStatus {
    public static final Status INVALID_ARGUMENT = Status.INVALID_ARGUMENT
        .withDescription("Invalid argument");
  }
}
