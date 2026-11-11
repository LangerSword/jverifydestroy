package io.jvd.web;

import java.lang.System.Logger;
import java.lang.System.Logger.Level;

/**
 * Starts the verification service.
 *
 * <p>The module ships as a library that a hosted site can embed, but it also runs on its own,
 * which is how a deployment is checked before it is put in front of visitors:</p>
 *
 * <pre>
 * java -cp web/target/classes:evidence/target/classes:log/target/classes io.jvd.web.Main 8080
 * </pre>
 *
 * <p>The port is the only argument. Port {@code 0} binds any free port, which is useful when
 * a script wants to start the service and then read the port it was given.</p>
 */
public final class Main {

    private static final Logger LOG = System.getLogger(Main.class.getName());

    private Main() {
    }

    /**
     * Starts the service and waits for it to stop.
     *
     * @param args the port to listen on; defaults to 8080
     */
    public static void main(String[] args) {
        int port = 8080;
        if (args.length > 0) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("the port must be a number, got: " + args[0]);
                System.exit(2);
            }
        }
        try {
            HttpApi api = new HttpApi(port);
            api.start();
            LOG.log(Level.INFO, "jverifydestroy verification service listening on port " + api.port());
            // Park the main thread; the server runs on its own worker threads.
            Thread.currentThread().join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            LOG.log(Level.ERROR, "could not start the verification service", e);
            System.exit(1);
        }
    }
}
