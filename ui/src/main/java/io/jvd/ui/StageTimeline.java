package io.jvd.ui;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.geom.Ellipse2D;
import java.awt.geom.Line2D;
import java.util.ArrayList;
import java.util.List;
import javax.swing.JComponent;
import javax.swing.Timer;

/**
 * A vertical stepper that shows what the tool is doing, one row per stage.
 *
 * <p>Each row carries a marker, a title, and a plain-language line. A row animates in
 * when its stage completes: the marker fills with the accent colour and the row fades up
 * from a slightly lower position. The fade is short — long fades make a fast operation
 * feel slow, which is the opposite of what the animation is for.
 *
 * <p>The timeline is the answer to "what is it doing, and is it stuck?" A log pane shows
 * text as it scrolls past; a stepper shows the <em>shape</em> of the work, so a user can
 * see at a glance that four of five stages are done and the fifth is running.
 */
final class StageTimeline extends JComponent {

    /** Where a stage sits in its own lifecycle. */
    enum Phase { PENDING, RUNNING, DONE, FAILED }

    record Stage(String title, String detail) {}

    private static final long FADE_MS = 220;

    private final List<Row> rows = new ArrayList<>();
    private final Timer timer;
    private long lastTick = System.nanoTime();
    private boolean running;
    private boolean populated;

    private static final class Row {
        final Stage stage;
        Phase phase = Phase.PENDING;
        double fade = 0.0;      // 0..1 entry animation
        float sweep = 0.0f;     // 0..1 running shimmer

        Row(Stage stage) { this.stage = stage; }
    }

    StageTimeline() {
        timer = new Timer(16, e -> tick());
        timer.setCoalesce(true);
    }

    /**
     * Declares the stages up front, so the user sees the shape of the work immediately.
     *
     * <p>Declaring them before the run matters: an empty panel reads as a broken panel.
     * The user should be able to look at the app and see what it is about to do.
     */
    void setStages(List<Stage> stages) {
        rows.clear();
        for (Stage s : stages) rows.add(new Row(s));
        populated = true;
        running = false;
        timer.stop();
        revalidate();
        repaint();
    }

    /**
     * Marks the stage at the given index as running, and the one before it as done.
     *
     * <p>Marking the previous stage as done matters because a stage that is running is not
     * the first thing that happened: the user wants to see the whole shape light up as
     * the work advances, not a single moving dot.
     */
    void markRunning(int index) {
        if (index < 0 || index >= rows.size()) return;
        for (int i = 0; i < index; i++) {
            if (rows.get(i).phase == Phase.PENDING) rows.get(i).phase = Phase.DONE;
        }
        rows.get(index).phase = Phase.RUNNING;
        startTicking();
        repaint();
    }

    /** Marks the stage at the given index as done and animates it in. */
    void markDone(int index) {
        if (index < 0 || index >= rows.size()) return;
        Row r = rows.get(index);
        r.phase = Phase.DONE;
        r.fade = 0.0;
        startTicking();
        repaint();
    }

    /** Marks the stage at the given index as failed. */
    void markFailed(int index) {
        if (index < 0 || index >= rows.size()) return;
        Row r = rows.get(index);
        r.phase = Phase.FAILED;
        r.fade = 0.0;
        startTicking();
        repaint();
    }

    /** Clears all stage state. */
    void reset() {
        for (Row r : rows) {
            r.phase = Phase.PENDING;
            r.fade = 0.0;
            r.sweep = 0.0f;
        }
        running = false;
        timer.stop();
        repaint();
    }

    private void startTicking() {
        running = true;
        if (!timer.isRunning()) {
            lastTick = System.nanoTime();
            timer.start();
        }
    }

    private void tick() {
        long now = System.nanoTime();
        float dt = (float) ((now - lastTick) / 1_000_000_000.0f);
        lastTick = now;
        boolean anyActive = false;
        for (Row r : rows) {
            if (r.fade < 1.0) {
                r.fade = Math.min(1.0, r.fade + (dt * 1000.0f) / FADE_MS);
                anyActive = true;
            }
            if (r.phase == Phase.RUNNING) {
                r.sweep = (r.sweep + dt * 1.6f) % 1.0f;
                anyActive = true;
            }
        }
        if (!anyActive) {
            timer.stop();
        }
        repaint();
    }

    @Override public Dimension getPreferredSize() {
        int h = Theme.px(30) + Math.max(1, rows.size()) * Theme.px(46);
        return new Dimension(Theme.px(420), h);
    }

    @Override protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

        int markerX = Theme.px(14);
        int top = Theme.px(10);
        int step = Theme.px(46);

        if (!populated || rows.isEmpty()) {
            // An empty panel reads as a broken panel. Say what will happen instead.
            g2.setFont(Theme.sans(12, Font.PLAIN));
            g2.setColor(Theme.FAINT);
            g2.drawString("The steps of a destruction appear here.", Theme.px(14), Theme.px(26));
            g2.setFont(Theme.sans(11, Font.PLAIN));
            g2.drawString("Choose a file and press Destroy and commit.", Theme.px(14), Theme.px(46));
            g2.dispose();
            return;
        }

        for (int i = 0; i < rows.size(); i++) {
            Row r = rows.get(i);
            int y = top + i * step;
            // A pending stage is visible but quiet: the user should see the whole plan
            // before the run starts, not only the part that has already happened.
            float alpha = r.phase == Phase.PENDING ? 0.5f : (float) r.fade;
            if (alpha <= 0f) continue;

            // The connector line to the next stage.
            if (i < rows.size() - 1) {
                Color lineColor = blend(Theme.BORDER_SOFT, Theme.ACCENT,
                        r.phase == Phase.DONE ? 0.35f : 0f);
                g2.setColor(withAlpha(lineColor, alpha));
                g2.setStroke(new BasicStroke(Theme.px(1)));
                g2.draw(new Line2D.Float(markerX + Theme.px(6), y + Theme.px(14),
                        markerX + Theme.px(6), y + step));
            }

            drawMarker(g2, markerX + Theme.px(6), y + Theme.px(8), r, alpha);

            g2.setFont(Theme.sans(13, Font.BOLD));
            g2.setColor(withAlpha(r.phase == Phase.FAILED ? Theme.RED : Theme.TEXT, alpha));
            g2.drawString(r.stage.title(), markerX + Theme.px(24), y + Theme.px(12));

            g2.setFont(Theme.sans(11, Font.PLAIN));
            g2.setColor(withAlpha(Theme.MUTED, alpha * 0.95f));
            g2.drawString(ellipsize(g2, r.stage.detail(), getWidth() - markerX - Theme.px(36)),
                    markerX + Theme.px(24), y + Theme.px(28));
        }
        g2.dispose();
    }

    private void drawMarker(Graphics2D g2, int cx, int cy, Row r, float alpha) {
        int rad = Theme.px(6);
        Color fill;
        Color ring;
        switch (r.phase) {
            case DONE -> {
                fill = Theme.ACCENT;
                ring = Theme.ACCENT;
            }
            case FAILED -> {
                fill = Theme.RED;
                ring = Theme.RED;
            }
            case RUNNING -> {
                fill = Theme.BG;
                ring = Theme.ACCENT;
            }
            default -> {
                fill = Theme.BG;
                ring = Theme.BORDER;
            }
        }
        g2.setColor(withAlpha(ring, alpha));
        g2.fill(new Ellipse2D.Float(cx - rad, cy - rad, rad * 2f, rad * 2f));
        if (r.phase != Phase.DONE && r.phase != Phase.FAILED) {
            g2.setColor(withAlpha(fill, alpha));
            g2.fill(new Ellipse2D.Float(cx - rad + Theme.px(2), cy - rad + Theme.px(2),
                    (rad - Theme.px(2)) * 2f, (rad - Theme.px(2)) * 2f));
        }
        if (r.phase == Phase.RUNNING) {
            // A single arc sweeping around the marker: it reads as "working" without
            // implying an unknown duration.
            g2.setColor(withAlpha(Theme.ACCENT, alpha * 0.85f));
            g2.setStroke(new BasicStroke(Theme.px(2), BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.drawArc(cx - rad - Theme.px(3), cy - rad - Theme.px(3),
                    (rad + Theme.px(3)) * 2, (rad + Theme.px(3)) * 2,
                    (int) (r.sweep * 360), 90);
        }
    }

    private static Color withAlpha(Color c, float alpha) {
        return new Color(c.getRed(), c.getGreen(), c.getBlue(),
                Math.max(0, Math.min(255, Math.round(c.getAlpha() * alpha))));
    }

    private static Color blend(Color a, Color b, float t) {
        float k = Math.max(0f, Math.min(1f, t));
        return new Color(
                Math.round(a.getRed() + (b.getRed() - a.getRed()) * k),
                Math.round(a.getGreen() + (b.getGreen() - a.getGreen()) * k),
                Math.round(a.getBlue() + (b.getBlue() - a.getBlue()) * k));
    }

    private static String ellipsize(Graphics2D g2, String text, int maxWidth) {
        if (maxWidth <= 0) return "";
        if (g2.getFontMetrics().stringWidth(text) <= maxWidth) return text;
        int n = text.length();
        while (n > 1 && g2.getFontMetrics().stringWidth(text.substring(0, n) + "…") > maxWidth) {
            n--;
        }
        return text.substring(0, n) + "…";
    }
}
