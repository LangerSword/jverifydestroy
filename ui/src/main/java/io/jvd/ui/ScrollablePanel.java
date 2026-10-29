package io.jvd.ui;

import javax.swing.*;
import java.awt.*;

/** A panel that tracks the scroll viewport width, so long notes wrap instead of clipping. */
final class ScrollablePanel extends JPanel implements Scrollable {
    ScrollablePanel() { super(); }

    @Override public Dimension getPreferredScrollableViewportSize() { return getPreferredSize(); }

    @Override public int getScrollableUnitIncrement(Rectangle visibleRect, int orientation, int direction) {
        return Theme.px(18);
    }

    @Override public int getScrollableBlockIncrement(Rectangle visibleRect, int orientation, int direction) {
        return Math.max(Theme.px(40), visibleRect.height - Theme.px(40));
    }

    @Override public boolean getScrollableTracksViewportWidth() { return true; }

    @Override public boolean getScrollableTracksViewportHeight() { return false; }
}
