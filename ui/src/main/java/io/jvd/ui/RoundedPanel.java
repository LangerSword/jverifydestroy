package io.jvd.ui;

import javax.swing.*;
import java.awt.*;

/** Flat card with a subtle border; no drop shadows, no gradients except the header. */
final class RoundedPanel extends JPanel {
    private final Color fill;
    private final Color border;
    private final int radius;

    RoundedPanel(LayoutManager layout, Color fill, Color border, int radius) {
        super(layout);
        this.fill = fill;
        this.border = border;
        this.radius = radius;
        setOpaque(false);
    }

    @Override protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setColor(fill);
        g2.fillRoundRect(0, 0, getWidth(), getHeight(), radius, radius);
        if (border != null) {
            g2.setColor(border);
            g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, radius, radius);
        }
        g2.dispose();
        super.paintComponent(g);
    }
}
