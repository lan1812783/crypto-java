package crypto;

import crypto.CryptoOuterClass.CipherSuite;
import org.openjdk.jmh.annotations.Benchmark;

public class DhEcdhBenchmark extends DhEcdhTest {
  @Benchmark
  public void dh() {
    dh_ecdh_client_server(CipherSuite.DH, true);
  }

  @Benchmark
  public void ecdh() {
    dh_ecdh_client_server(CipherSuite.ECDH, true);
  }
}
