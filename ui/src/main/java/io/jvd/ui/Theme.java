package io.jvd.ui;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.border.EmptyBorder;
import java.awt.*;

/** Dark editorial theme and a screen-relative scale. All sizes are logical pixels times scale. */
final class Theme {
    static final Color BG = new Color(0x0B0D10);
    static final Color SURFACE = new Color(0x12151A);
    static final Color ELEVATED = new Color(0x171B22);
    static final Color FIELD = new Color(0x0E1116);
    static final Color BORDER = new Color(0x2A303B);
    static final Color BORDER_SOFT = new Color(0x20252E);
    static final Color TEXT = new Color(0xECE9E2);
    static final Color MUTED = new Color(0xA6ADBA);
    static final Color FAINT = new Color(0x7C8492);
    static final Color ACCENT = new Color(0xC8F56A);
    static final Color ACCENT_HOVER = new Color(0xDCFF8C);
    static final Color GREEN = new Color(0x7EE2A8);
    static final Color AMBER = new Color(0xF2C66D);
    static final Color RED = new Color(0xFF7B72);

    private static double scale = 1.0;

    private Theme() {}

    static void init(Double override) {
        double s;
        if (override != null) {
            s = override;
        } else {
            String prop = System.getProperty("jvd.ui.scale");
            if (prop == null) prop = System.getenv("JVD_UI_SCALE");
            if (prop != null) {
                try { s = Double.parseDouble(prop); } catch (NumberFormatException e) { s = auto(); }
            } else {
                s = auto();
            }
        }
        scale = Math.max(1.0, Math.min(2.0, Math.round(s * 100.0) / 100.0));
        applyDefaults();
    }

    private static double auto() {
        int width = Toolkit.getDefaultToolkit().getScreenSize().width;
        return Math.max(1.0, Math.min(1.7, width / 1920.0));
    }

    static double scale() { return scale; }

    static int px(double n) { return (int) Math.round(n * scale); }

    static Font sans(int size, int style) { return new Font("SansSerif", style, px(size)); }

    static Font serif(int size, int style) { return new Font("Serif", style, px(size)); }

    static Font mono(int size, int style) { return new Font("Monospaced", style, px(size)); }

    static Border fieldBorder() {
        return BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER, 1, true),
                new EmptyBorder(px(8), px(10), px(8), px(10)));
    }

    static JLabel section(String text) {
        JLabel l = new JLabel(text);
        l.setFont(mono(10, Font.BOLD));
        l.setForeground(MUTED);
        return l;
    }

    /** A dark flat button with a real hover state. */
    static final class FlatButton extends JButton {
        private final boolean primary;
        private final Color base;
        private final Color hover;
        private boolean over;

        FlatButton(String text, boolean primary) {
            super(text);
            this.primary = primary;
            this.base = primary ? ACCENT : ELEVATED;
            this.hover = primary ? ACCENT_HOVER : new Color(0x202631);
            setFont(mono(12, Font.BOLD));
            setForeground(primary ? BG : TEXT);
            setOpaque(false);
            setContentAreaFilled(false);
            setBorderPainted(false);
            setFocusPainted(false);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            setBorder(new EmptyBorder(px(10), px(14), px(10), px(14)));
            addMouseListener(new java.awt.event.MouseAdapter() {
                @Override public void mouseEntered(java.awt.event.MouseEvent e) { over = true; repaint(); }
                @Override public void mouseExited(java.awt.event.MouseEvent e) { over = false; repaint(); }
            });
        }

        @Override protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(over ? hover : base);
            g2.fillRoundRect(0, 0, getWidth(), getHeight(), px(10), px(10));
            if (!primary) {
                g2.setColor(BORDER);
                g2.drawRoundRect(0, 0, getWidth() - 1, getHeight() - 1, px(10), px(10));
            }
            g2.dispose();
            super.paintComponent(g);
        }
    }

    private static void applyDefaults() {
        UIManager.put("Panel.background", BG);
        UIManager.put("Label.foreground", TEXT);
        UIManager.put("Label.font", sans(13, Font.PLAIN));
        UIManager.put("TextField.background", FIELD);
        UIManager.put("TextField.foreground", TEXT);
        UIManager.put("TextField.caretForeground", ACCENT);
        UIManager.put("TextField.font", mono(12, Font.PLAIN));
        UIManager.put("TextField.border", fieldBorder());
        UIManager.put("TextField.selectionBackground", new Color(0x33402A));
        UIManager.put("TextField.selectionForeground", TEXT);
        UIManager.put("ComboBox.background", FIELD);
        UIManager.put("ComboBox.foreground", TEXT);
        UIManager.put("ComboBox.font", mono(12, Font.PLAIN));
        UIManager.put("ComboBox.border", BorderFactory.createLineBorder(BORDER, 1, true));
        UIManager.put("ComboBox.selectionBackground", new Color(0x33402A));
        UIManager.put("ComboBox.selectionForeground", TEXT);
        UIManager.put("Spinner.background", FIELD);
        UIManager.put("Spinner.foreground", TEXT);
        UIManager.put("Spinner.border", BorderFactory.createLineBorder(BORDER, 1, true));
        UIManager.put("FormattedTextField.background", FIELD);
        UIManager.put("FormattedTextField.foreground", TEXT);
        UIManager.put("CheckBox.background", SURFACE);
        UIManager.put("CheckBox.foreground", TEXT);
        UIManager.put("CheckBox.font", sans(12, Font.PLAIN));
        UIManager.put("CheckBox.focus", BG);
        UIManager.put("TabbedPane.background", ELEVATED);
        UIManager.put("TabbedPane.foreground", MUTED);
        UIManager.put("TabbedPane.selected", ELEVATED);
        UIManager.put("TabbedPane.selectedForeground", TEXT);
        UIManager.put("TabbedPane.font", mono(11, Font.BOLD));
        UIManager.put("TabbedPane.tabAreaBackground", ELEVATED);
        UIManager.put("TabbedPane.contentBorderInsets", new Insets(0, 0, 0, 0));
        UIManager.put("TabbedPane.focus", ELEVATED);
        UIManager.put("ScrollPane.background", SURFACE);
        UIManager.put("Viewport.background", SURFACE);
        UIManager.put("TextArea.background", FIELD);
        UIManager.put("TextArea.foreground", TEXT);
        UIManager.put("TextArea.font", mono(12, Font.PLAIN));
        UIManager.put("TextArea.caretForeground", ACCENT);
        UIManager.put("TextPane.background", FIELD);
        UIManager.put("TextPane.foreground", TEXT);
        UIManager.put("TextPane.font", mono(12, Font.PLAIN));
        UIManager.put("ToolTip.background", ELEVATED);
        UIManager.put("ToolTip.foreground", TEXT);
        UIManager.put("ToolTip.font", sans(12, Font.PLAIN));
        UIManager.put("OptionPane.background", SURFACE);
        UIManager.put("OptionPane.messageForeground", TEXT);
        UIManager.put("OptionPane.messageFont", sans(13, Font.PLAIN));
        UIManager.put("Button.font", mono(12, Font.BOLD));
        UIManager.put("ScrollBar.width", px(10));
        UIManager.put("ScrollBar.background", SURFACE);
        UIManager.put("ScrollBar.thumb", BORDER);
    }
}
