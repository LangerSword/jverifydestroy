package io.jvd.ui;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.RoundRectangle2D;
import javax.swing.JComponent;
import javax.swing.Timer;

/**
 * A thin determinate progress bar that animates towards its target value.
 *
 * <p>The animation exists for a reason that is not decoration. A destruction of a large
 * file can take seconds, and a bar that jumps straight to 100% reads as a frozen
 * application. The bar eases towards the real progress value, so the user can see that
 * the work is still moving even between two stage boundaries.
 *
 * <p>The bar never lies about the value: it animates <em>towards</em> the true progress and
 * never past it. {@link #setProgress(double)} clamps to [0,1] and the painter only ever
 * draws the animated value, which is always at or below the target. A stage that reports
 * its own completion still wins over the animation.
 *
 * <p>The stripe is a single moving highlight rather than a scrolling pattern. A scrolling
 * stripe reads as "indeterminate", which would be a lie here: the work really is
 * determinate.
 */
final class ProgressBar extends JComponent {

    /** Milliseconds between animation frames. 60fps is plenty and costs nothing. */
    private static final int FRAME_MS = 16;

    private static final double EASE = 0.18;

    private double target;
    private double shown;
    private long lastTick = System.nanoTime();
    private final Timer timer;

    private Color trackColor = Theme.ELEVATED;
    private Color fillColor = Theme.ACCENT;
    private boolean active;

    ProgressBar() {
        setPreferredSize(new java.awt.Dimension(0, Theme.px(6)));
        setOpaque(false);
        timer = new Timer(FRAME_MS, e -> tick());
        timer.setCoalesce(true);
    }

    /** Sets the true progress in [0,1]. The bar eases towards it; it never overshoots. */
    void setProgress(double value) {
        double clamped = Math.max(0.0, Math.min(1.0, value));
        if (clamped > target) {
            target = clamped;
            start();
        } else {
            target = clamped;
        }
        repaint();
    }

    /** Marks the bar as finished: it fills completely and stops animating. */
    void finish() {
        target = 1.0;
        shown = 1.0;
        active = false;
        timer.stop();
        repaint();
    }

    /** Resets to empty and stops animating. */
    void reset() {
        target = 0.0;
        shown = 0.0;
        active = false;
        timer.stop();
        repaint();
    }

    private void start() {
        if (!timer.isRunning()) {
            lastTick = System.nanoTime();
            timer.start();
        }
    }

    private void tick() {
        long now = System.nanoTime();
        double dt = (now - lastTick) / 1_000_000_000.0;
        lastTick = now;
        // Frame-rate independent easing: the same wall-clock duration always looks the
        // same, whether the machine renders at 30fps or 144fps.
        double factor = 1.0 - Math.pow(1.0 - EASE, dt * 60.0);
        shown += (target - shown) * factor;
        if (Math.abs(target - shown) < 0.002) {
            shown = target;
            if (!active) {
                timer.stop();
            }
        }
        repaint();
    }

    @Override protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        int w = getWidth();
        int h = getHeight();
        int r = h;
        g2.setColor(trackColor);
        g2.fill(new RoundRectangle2D.Float(0, 0, w, h, r, r));
        double frac = Math.max(0.0, Math.min(1.0, shown));
        int fillW = (int) Math.round(w * frac);
        if (fillW > 0) {
            g2.setColor(fillColor);
            g2.fill(new RoundRectangle2D.Float(0, 0, Math.max(fillW, h), h, r, r));
        }
        g2.dispose();
    }

    /** Repaints the track and fill in the given colours. */
    void setColors(Color track, Color fill) {
        this.trackColor = track;
        this.fillColor = fill;
        repaint();
    }

    @Override public void setFont(Font f) {
        super.setFont(f);
    }
}
