package crypto;

import com.google.protobuf.ByteString;
import crypto.CryptoOuterClass.CipherSuite;
import crypto.CryptoOuterClass.HandshakeData;
import crypto.CryptoOuterClass.OpenConnectionRequest;
import crypto.CryptoOuterClass.OpenConnectionResponse;
import io.grpc.Grpc;
import io.grpc.InsecureServerCredentials;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.KeyAgreement;

/** Cryptographic server. */
public class CryptoServer {
  private static final Logger logger = Logger.getLogger(CryptoServer.class.getName());

  private final int port;
  private final Server server;

  public CryptoServer(int port) throws IOException {
    this(Grpc.newServerBuilderForPort(port, InsecureServerCredentials.create()), port);
  }

  public CryptoServer(ServerBuilder<?> serverBuilder, int port) throws IOException {
    this.port = port;
    server = serverBuilder.addService(new CryptoService()).build();
  }

  /** Starts serving requests. */
  public void start() throws IOException {
    server.start();
    logger.info("Server started, listening on " + port);
    Runtime.getRuntime()
        .addShutdownHook(
            new Thread() {
              @Override
              public void run() {
                // Use stderr here since the logger may have been reset by its JVM shutdown
                // hook.
                System.err.println("*** shutting down gRPC server since JVM is shutting down");
                try {
                  CryptoServer.this.stop();
                } catch (InterruptedException e) {
                  e.printStackTrace(System.err);
                }
                System.err.println("*** server shut down");
              }
            });
  }

  /** Stops serving requests and shutdown resources. */
  public void stop() throws InterruptedException {
    if (server != null) {
      server.shutdown().awaitTermination(30, TimeUnit.SECONDS);
    }
  }

  /** Await termination on the main thread since the grpc library uses daemon threads. */
  private void blockUntilShutdown() throws InterruptedException {
    if (server != null) {
      server.awaitTermination();
    }
  }

  /** Constructs and starts a cryptographic server. */
  public static void main(String[] args) throws Exception {
    CryptoServer server = new CryptoServer(50051);
    server.start();
    server.blockUntilShutdown();
  }

  private static class CryptoService extends CryptoGrpc.CryptoImplBase {
    @Override
    public void openConnection(
        OpenConnectionRequest request, StreamObserver<OpenConnectionResponse> responseObserver) {
      for (HandshakeData clientHandshakeData : request.getHandshakeDataListList()) {
        CipherSuite clientCipherSuite = clientHandshakeData.getCipherSuite();
        ByteString clientData = clientHandshakeData.getData();

        if (!isSupported(clientCipherSuite)) {
          continue;
        }

        HandshakeData serverHandshakeData = getServerHandshakeData(clientCipherSuite, clientData);
        if (serverHandshakeData == null) {
          continue;
        }
        responseObserver.onNext(
            OpenConnectionResponse.newBuilder().setHandshakeData(serverHandshakeData).build());
        responseObserver.onCompleted();
        return;
      }
      responseObserver.onError(new StatusRuntimeException(CryptoDef.CryptoStatus.INVALID_ARGUMENT));
    }

    private boolean isSupported(CipherSuite cipherSuite) {
      // TODO
      return true;
    }

    private HandshakeData getServerHandshakeData(
        CipherSuite clientCipherSuite, ByteString clientData) {
      byte[] serverPublicKeyBuf = null;
      switch (clientCipherSuite) {
        case DH:
          serverPublicKeyBuf = dh(DiffieHellman.getInstance(), clientData.toByteArray());
          break;
        case ECDH:
          serverPublicKeyBuf =
              dh(EllipticCurveDiffieHellman.getInstance(), clientData.toByteArray());
          break;
        default:
          return null;
      }
      if (serverPublicKeyBuf == null) {
        return null;
      }
      return HandshakeData.newBuilder()
          .setCipherSuite(clientCipherSuite)
          .setData(ByteString.copyFrom(serverPublicKeyBuf))
          .build();
    }

    private byte[] dh(DiffieHellman algoInst, byte[] peerPublicKeyBuf) {
      PublicKey peerPublicKey = algoInst.getPeerPublicKey(peerPublicKeyBuf);
      if (peerPublicKey == null) {
        return null;
      }
      KeyPair keyPair = algoInst.generateKeyPair(peerPublicKey);
      if (keyPair == null) {
        return null;
      }

      byte[] publicKeyBuf = keyPair.getPublic().getEncoded();
      logger.log(Level.INFO, "Server's public key: " + Util.toHexString(publicKeyBuf));

      KeyAgreement keyAgreement = algoInst.getKeyAgreement(keyPair);
      if (keyAgreement == null) {
        return null;
      }
      boolean doPhaseOk = algoInst.doPhase(keyAgreement, peerPublicKey);
      if (!doPhaseOk) {
        return null;
      }

      byte[] sharedSecret = keyAgreement.generateSecret();
      logger.log(
          Level.INFO, "Shared secret generated by server: " + Util.toHexString(sharedSecret, ":"));

      return publicKeyBuf;
    }
  }
}
