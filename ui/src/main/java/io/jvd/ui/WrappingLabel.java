package io.jvd.ui;

import javax.swing.JTextArea;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;

/**
 * A caption that wraps to the width it is given.
 *
 * <p>Swing has no wrapping label, and the usual workarounds both fail in this layout.
 * An HTML label carries its own fixed pixel width, so it does not follow the panel: the
 * text is laid out at a width the panel may not have. A {@code JTextPane} reports its
 * preferred height from its own preferred width, so inside a {@code BoxLayout} on the Y
 * axis — which sizes children to their preferred width — it is sized to its longest line
 * and never wraps.
 *
 * <p>A {@code JTextArea} with line wrapping does not have that problem: it wraps to
 * whatever width it is given, and it reports a preferred height for the width it
 * currently has. The only thing it needs is for the row that holds it to be told how tall
 * to be once the width is known, which is what {@link #heightFor(int)} is for.
 */
final class WrappingLabel extends JTextArea {

    private final String text;
    private final Color color;
    private final Font font;

    WrappingLabel(String text, Font font, Color color) {
        this.text = text;
        this.font = font;
        this.color = color;
        setEditable(false);
        setFocusable(false);
        setOpaque(false);
        setLineWrap(true);
        setWrapStyleWord(true);
        setFont(font);
        setForeground(color);
        setText(text);
    }

    /**
     * The height the text needs when it is wrapped at the given width.
     *
     * <p>A wrapping caption cannot know its height until it knows its width, and the
     * width is not known when a row is first sized. So the height is computed on demand
     * for a specific width, and the row that holds the caption asks for it again after
     * the row has been laid out.
     */
    int heightFor(int width) {
        int w = Math.max(Theme.px(60), width);
        setSize(w, Theme.px(20));
        // The area re-wraps at its new size, so its preferred height is now the height of
        // the wrapped result.
        int h = getPreferredSize().height;
        return Math.max(h, getFontMetrics(font).getHeight() + 2);
    }

    @Override public Dimension getPreferredSize() {
        // A narrow preferred width stops a BoxLayout from giving this component the width
        // of its longest line, which is what stops it from ever wrapping. The height comes
        // from the superclass, which measures the wrapped text at the current width.
        int w = Math.max(Theme.px(80), getWidth() > 0 ? getWidth() : Theme.px(240));
        setSize(w, getHeight() > 0 ? getHeight() : Theme.px(20));
        Dimension d = super.getPreferredSize();
        return new Dimension(w, d.height);
    }

    @Override public Dimension getMaximumSize() {
        return new Dimension(Integer.MAX_VALUE, super.getPreferredSize().height);
    }
}
