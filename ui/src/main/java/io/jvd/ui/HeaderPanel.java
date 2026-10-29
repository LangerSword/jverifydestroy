package io.jvd.ui;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/** The only decorative surface: a quiet gradient, an accent rule, and a status badge. */
final class HeaderPanel extends JPanel {
    HeaderPanel() {
        super(new BorderLayout());
        setOpaque(false);
        setBorder(new EmptyBorder(Theme.px(24), Theme.px(28), Theme.px(20), Theme.px(28)));
        setPreferredSize(new Dimension(0, Theme.px(118)));

        JPanel left = new JPanel();
        left.setOpaque(false);
        left.setLayout(new BoxLayout(left, BoxLayout.Y_AXIS));

        JLabel title = new JLabel("jVerifyDestroy");
        title.setFont(Theme.serif(30, Font.BOLD));
        title.setForeground(Theme.TEXT);
        title.setAlignmentX(Component.LEFT_ALIGNMENT);
        left.add(title);
        left.add(Box.createVerticalStrut(Theme.px(8)));

        JPanel tagline = new JPanel(new FlowLayout(FlowLayout.LEFT, Theme.px(8), 0));
        tagline.setOpaque(false);
        tagline.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel mark = new JLabel("■");
        mark.setForeground(Theme.ACCENT);
        mark.setFont(Theme.mono(9, Font.PLAIN));
        JLabel sub = new JLabel("DESTROY  →  MEASURE  →  PROVE");
        sub.setFont(Theme.mono(10, Font.BOLD));
        sub.setForeground(Theme.MUTED);
        tagline.add(mark);
        tagline.add(sub);
        left.add(tagline);

        JLabel badge = new JLabel("LOGICAL LEVEL ONLY");
        badge.setFont(Theme.mono(9, Font.BOLD));
        badge.setForeground(Theme.AMBER);
        badge.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(new Color(0x5A4A2A), 1, true),
                new EmptyBorder(Theme.px(6), Theme.px(9), Theme.px(6), Theme.px(9))));
        JPanel right = new JPanel(new FlowLayout(FlowLayout.RIGHT, 0, 0));
        right.setOpaque(false);
        right.add(badge);

        add(left, BorderLayout.WEST);
        add(right, BorderLayout.EAST);
    }

    @Override protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        GradientPaint gp = new GradientPaint(0, 0, new Color(0x101318), getWidth(), getHeight(),
                new Color(0x1A1F27));
        g2.setPaint(gp);
        g2.fillRect(0, 0, getWidth(), getHeight());
        g2.setColor(new Color(0x2A303B));
        g2.fillRect(0, getHeight() - 1, getWidth(), 1);
        g2.setColor(new Color(0xC8F56A));
        g2.fillRect(Theme.px(28), getHeight() - Theme.px(3), Theme.px(44), Theme.px(2));
        g2.setColor(Theme.ACCENT);
        g2.setComposite(AlphaComposite.getInstance(AlphaComposite.SRC_OVER, 0.06f));
        g2.fillOval(getWidth() - Theme.px(210), -Theme.px(70), Theme.px(300), Theme.px(300));
        g2.dispose();
        super.paintComponent(g);
    }
}
