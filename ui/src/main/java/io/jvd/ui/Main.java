package io.jvd.ui;

import javax.imageio.ImageIO;
import javax.swing.*;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.File;

/** Launches the Swing desktop app. {@code --smoke} builds/disposes; {@code --screenshot=FILE} captures it. */
public final class Main {
    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (Exception ignored) {
            // Keep the default look and feel.
        }
        boolean smoke = args.length > 0 && args[0].equals("--smoke");
        String screenshot = null;
        for (String a : args) if (a.startsWith("--screenshot=")) screenshot = a.substring("--screenshot=".length());

        if (screenshot != null) {
            String out = screenshot;
            MainFrame[] holder = new MainFrame[1];
            try {
                SwingUtilities.invokeAndWait(() -> {
                    holder[0] = new MainFrame();
                    holder[0].setVisible(true);
                    holder[0].toFront();
                });
                Thread.sleep(1200);
                MainFrame f = holder[0];
                BufferedImage img = new BufferedImage(Math.max(1, f.getWidth()), Math.max(1, f.getHeight()),
                        BufferedImage.TYPE_INT_ARGB);
                java.awt.Graphics2D g = img.createGraphics();
                f.printAll(g);
                g.dispose();
                ImageIO.write(img, "png", new File(out));
                SwingUtilities.invokeAndWait(f::dispose);
                System.out.println("SHOT_OK " + out);
                System.exit(0);
            } catch (Throwable t) {
                t.printStackTrace();
                System.exit(1);
            }
        }

        SwingUtilities.invokeLater(() -> {
            try {
                MainFrame frame = new MainFrame();
                if (smoke) {
                    frame.pack();
                    System.out.println("UI_OK");
                    frame.dispose();
                    System.exit(0);
                }
                frame.setVisible(true);
            } catch (Throwable t) {
                t.printStackTrace();
                System.exit(1);
            }
        });
    }
}
