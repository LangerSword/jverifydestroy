package io.jvd.ui;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;

/** Monospaced, color-coded log. Color is semantic, not decoration. */
final class LogPane extends JTextPane {
    private final StyledDocument doc;

    LogPane() {
        setEditable(false);
        setBackground(Theme.FIELD);
        setForeground(Theme.TEXT);
        setFont(Theme.mono(12, Font.PLAIN));
        setMargin(new Insets(Theme.px(12), Theme.px(14), Theme.px(12), Theme.px(14)));
        setCaretColor(Theme.ACCENT);
        doc = getStyledDocument();
    }

    void append(String line) {
        SimpleAttributeSet a = new SimpleAttributeSet();
        StyleConstants.setFontFamily(a, "Monospaced");
        StyleConstants.setFontSize(a, Theme.px(12));
        StyleConstants.setForeground(a, colorFor(line));
        StyleConstants.setLineSpacing(a, 0.12f);
        try {
            doc.insertString(doc.getLength(), line + "\n", a);
            setCaretPosition(doc.getLength());
        } catch (BadLocationException e) {
            throw new IllegalStateException(e);
        }
    }

    void clear() {
        try { doc.remove(0, doc.getLength()); } catch (BadLocationException ignored) { }
    }

    private Color colorFor(String line) {
        if (line.startsWith("ERROR")) return Theme.RED;
        if (line.startsWith("==")) return Theme.ACCENT;
        if (line.contains("COMMITTED") || line.contains("verify: VALID")) return Theme.GREEN;
        if (line.contains("ABORTED") || line.contains("FAIL") || line.contains("INVALID")) return Theme.AMBER;
        if (line.startsWith("  check:") || line.startsWith("  ")) return Theme.MUTED;
        return Theme.TEXT;
    }
}
