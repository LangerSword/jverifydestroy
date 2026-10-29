import javax.crypto.spec.SecretKeySpec;
public class DestroyProbe {
  public static void main(String[] a) throws Exception {
    SecretKeySpec k = new SecretKeySpec(new byte[16], "AES");
    System.out.println("isDestroyed before=" + k.isDestroyed());
    try { k.destroy(); System.out.println("destroy returned normally"); }
    catch (Exception e) { System.out.println("destroy threw " + e.getClass().getName() + ": " + e.getMessage()); }
    System.out.println("isDestroyed after=" + k.isDestroyed());
  }
}
