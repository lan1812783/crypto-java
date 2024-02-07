package crypto;

public class Util {
  /** Converts a byte to hex digit and writes to the supplied buffer */
  public static void byte2hex(byte b, StringBuffer buf) {
    char[] hexChars = {
        '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };
    int high = ((b & 0xf0) >> 4);
    int low = (b & 0x0f);
    buf.append(hexChars[high]);
    buf.append(hexChars[low]);
  }

  public static String toHexString(byte[] block) {
    return toHexString(block, "");
  }

  /** Converts a byte array to hex string */
  public static String toHexString(byte[] block, String delim) {
    StringBuffer buf = new StringBuffer();
    int len = block.length;
    for (int i = 0; i < len; i++) {
      byte2hex(block[i], buf);
      if (i < len - 1) {
        buf.append(delim);
      }
    }
    return buf.toString();
  }
}
