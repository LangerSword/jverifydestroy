package io.jvd.ui;

import io.jvd.txn.Method;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import java.util.function.Consumer;

/** Swing desktop app: destroy, inspect evidence, verify the log, recover. */
public final class MainFrame extends JFrame {
    private final JTextField targetField = new JTextField();
    private final JTextField workField = new JTextField();
    private final JTextField imageField = new JTextField();
    private final JTextField canaryField = new JTextField();
    private final JComboBox<String> modeBox = new JComboBox<>(new String[]{
            "Crypto-shred  /  key destruction", "Overwrite  /  NIST Clear (weak on flash)"});
    private final JSpinner graceSpinner = new JSpinner(new SpinnerNumberModel(0, 0, 86_400, 1));
    private final JCheckBox requireBox = new JCheckBox("Require raw-media validation (roll back if NOT_CHECKABLE)");
    private final LogPane logPane = new LogPane();
    private final JTextArea evidenceArea = new JTextArea();
    private final JTabbedPane tabs = new JTabbedPane();
    private final JLabel status = new JLabel("Ready");
    private final JLabel statusDot = new JLabel("●");
    private final JLabel stateMetric = new JLabel("—");
    private final JLabel validationMetric = new JLabel("—");
    private final JLabel assuranceMetric = new JLabel("—");
    private final JLabel controlsMetric = new JLabel("—");
    private final JButton destroyBtn = new Theme.FlatButton("Destroy and commit", true);
    private final JButton verifyBtn = new Theme.FlatButton("Verify evidence", false);
    private final JButton recoverBtn = new Theme.FlatButton("Recover", false);
    private final JButton testBtn = new Theme.FlatButton("Memory self-test", false);
    private JSplitPane splitPane;

    public MainFrame() {
        super("jVerifyDestroy — verifiable logical destruction");
        setDefaultCloseOperation(EXIT_ON_CLOSE);

        workField.setText(Path.of(System.getProperty("user.home"), ".jvd-work").toString());
        evidenceArea.setEditable(false);
        evidenceArea.setFont(Theme.mono(12, Font.PLAIN));
        evidenceArea.setBackground(Theme.FIELD);
        evidenceArea.setForeground(Theme.TEXT);
        evidenceArea.setMargin(new Insets(Theme.px(12), Theme.px(14), Theme.px(12), Theme.px(14)));

        JPanel root = new JPanel(new BorderLayout());
        root.setBackground(Theme.BG);
        root.add(new HeaderPanel(), BorderLayout.NORTH);

        JPanel body = new JPanel(new BorderLayout());
        body.setOpaque(false);
        body.setBorder(new EmptyBorder(Theme.px(16), Theme.px(24), Theme.px(16), Theme.px(24)));

        splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, buildLeft(), buildRight());
        splitPane.setBorder(null);
        splitPane.setOpaque(false);
        splitPane.setDividerSize(Theme.px(8));
        splitPane.setResizeWeight(0.34);
        splitPane.setContinuousLayout(true);
        body.add(splitPane, BorderLayout.CENTER);
        root.add(body, BorderLayout.CENTER);
        root.add(buildFooter(), BorderLayout.SOUTH);
        setContentPane(root);

        int screenW = Toolkit.getDefaultToolkit().getScreenSize().width;
        int screenH = Toolkit.getDefaultToolkit().getScreenSize().height;
        int w = Math.min(Theme.px(1500), Math.max(Theme.px(1180), (int) (screenW * 0.70)));
        int h = Math.min(Theme.px(1100), Math.max(Theme.px(800), (int) (screenH * 0.90)));
        setSize(w, h);
        setMinimumSize(new Dimension(Theme.px(1040), Theme.px(700)));
        setLocationRelativeTo(null);

        destroyBtn.addActionListener(e -> doDestroy());
        verifyBtn.addActionListener(e -> doVerify());
        recoverBtn.addActionListener(e -> doRecover());
        testBtn.addActionListener(e -> doSelfTest());
        destroyBtn.setToolTipText("Destroy the file and commit the evidence");
        verifyBtn.setToolTipText("Check the log, checkpoint, witness, and record signatures offline");
        recoverBtn.setToolTipText("Restore a transaction that crashed before COMMIT");
        testBtn.setToolTipText("Run one control-validated memory wipe and scan a child JVM");

        logPane.append("Ready. Select a file and a work directory, then Destroy.");
        logPane.append("The work directory holds keys, journal, vault, and checkpoints.");
        logPane.append("A COMMITTED transaction cannot be restored; that is the guarantee.");
    }

    public void setSplitFraction(double fraction) {
        splitPane.setDividerLocation(fraction);
    }

    private JComponent buildLeft() {
        JPanel form = new ScrollablePanel();
        form.setOpaque(false);
        form.setLayout(new BoxLayout(form, BoxLayout.Y_AXIS));
        form.setBorder(new EmptyBorder(0, 0, Theme.px(8), Theme.px(6)));

        RoundedPanel target = card("01 / TARGET");
        addGroup(target, 0, "FILE TO DESTROY", targetField, this::browseTarget);
        addGroup(target, 1, "WORK DIRECTORY", workField, this::browseWork);

        RoundedPanel method = card("02 / DESTRUCTION");
        addGroup(method, 0, "METHOD", modeBox, null);
        JPanel options = new JPanel(new BorderLayout(0, Theme.px(10)));
        options.setOpaque(false);
        JPanel grace = new JPanel(new FlowLayout(FlowLayout.LEFT, Theme.px(8), 0));
        grace.setOpaque(false);
        grace.add(Theme.section("GRACE"));
        graceSpinner.setPreferredSize(new Dimension(Theme.px(90), Theme.px(34)));
        grace.add(graceSpinner);
        grace.add(Theme.section("SECONDS BEFORE COMMIT"));
        options.add(grace, BorderLayout.NORTH);
        requireBox.setOpaque(false);
        options.add(requireBox, BorderLayout.CENTER);
        add(options, method, 2);

        RoundedPanel witness = card("03 / RAW-MEDIA WITNESS  ·  OPTIONAL");
        addGroup(witness, 0, "RAW IMAGE", imageField, this::browseImage);
        addGroup(witness, 1, "CANARY HEX", canaryField, null);
        JTextArea note = new JTextArea("The image must contain the canary before destruction; "
                + "otherwise validation is NOT_CHECKABLE. Physical flash is never verified.");
        note.setFont(Theme.sans(11, Font.PLAIN));
        note.setForeground(Theme.MUTED);
        note.setOpaque(false);
        note.setEditable(false);
        note.setFocusable(false);
        note.setLineWrap(true);
        note.setWrapStyleWord(true);
        note.setRows(3);
        note.setColumns(36);
        note.setBorder(null);
        add(note, witness, 3);

        fit(target);
        fit(method);
        fit(witness);
        form.add(target);
        form.add(Box.createVerticalStrut(Theme.px(10)));
        form.add(method);
        form.add(Box.createVerticalStrut(Theme.px(10)));
        form.add(witness);
        form.add(Box.createVerticalStrut(Theme.px(4)));

        JScrollPane formScroll = new JScrollPane(form,
                ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
                ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
        formScroll.setBorder(null);
        formScroll.setOpaque(false);
        formScroll.getViewport().setOpaque(false);
        formScroll.getVerticalScrollBar().setUnitIncrement(Theme.px(18));

        JPanel actions = new JPanel();
        actions.setOpaque(false);
        actions.setLayout(new BoxLayout(actions, BoxLayout.Y_AXIS));

        destroyBtn.setAlignmentX(Component.LEFT_ALIGNMENT);
        destroyBtn.setMaximumSize(new Dimension(Integer.MAX_VALUE, Theme.px(46)));
        destroyBtn.setPreferredSize(new Dimension(10, Theme.px(46)));
        actions.add(destroyBtn);
        actions.add(Box.createVerticalStrut(Theme.px(8)));

        JPanel secondary = new JPanel(new GridLayout(1, 3, Theme.px(8), 0));
        secondary.setOpaque(false);
        secondary.setAlignmentX(Component.LEFT_ALIGNMENT);
        secondary.setMaximumSize(new Dimension(Integer.MAX_VALUE, Theme.px(40)));
        secondary.add(verifyBtn);
        secondary.add(recoverBtn);
        secondary.add(testBtn);
        actions.add(secondary);
        actions.add(Box.createVerticalStrut(Theme.px(10)));

        JLabel hint = new JLabel("Commit is irreversible. Rollback is available only before COMMIT.");
        hint.setFont(Theme.mono(10, Font.PLAIN));
        hint.setForeground(Theme.MUTED);
        hint.setAlignmentX(Component.LEFT_ALIGNMENT);
        actions.add(hint);

        JPanel left = new JPanel(new BorderLayout(0, Theme.px(12)));
        left.setOpaque(false);
        left.setBorder(new EmptyBorder(0, 0, 0, Theme.px(20)));
        left.setPreferredSize(new Dimension(Theme.px(560), 0));
        left.add(formScroll, BorderLayout.CENTER);
        left.add(actions, BorderLayout.SOUTH);
        return left;
    }

    private JComponent buildRight() {
        RoundedPanel right = new RoundedPanel(new BorderLayout(), Theme.ELEVATED, Theme.BORDER_SOFT, Theme.px(12));
        right.setBorder(new EmptyBorder(Theme.px(10), Theme.px(10), Theme.px(10), Theme.px(10)));

        JPanel head = new JPanel(new BorderLayout());
        head.setOpaque(false);
        head.setBorder(new EmptyBorder(Theme.px(2), Theme.px(8), Theme.px(8), Theme.px(8)));
        head.add(Theme.section("EVIDENCE STREAM"), BorderLayout.WEST);
        JLabel local = new JLabel("● LOCAL WITNESS");
        local.setFont(Theme.mono(9, Font.BOLD));
        local.setForeground(Theme.GREEN);
        head.add(local, BorderLayout.EAST);

        JPanel north = new JPanel(new BorderLayout(0, Theme.px(10)));
        north.setOpaque(false);
        north.add(head, BorderLayout.NORTH);
        north.add(metrics(), BorderLayout.CENTER);
        right.add(north, BorderLayout.NORTH);

        tabs.setOpaque(false);
        tabs.setBorder(null);
        tabs.addTab("LOG", scroll(logPane));
        tabs.addTab("EVIDENCE JSON", scroll(evidenceArea));
        right.add(tabs, BorderLayout.CENTER);
        return right;
    }

    private JComponent metrics() {
        JPanel row = new JPanel(new GridLayout(1, 4, Theme.px(8), 0));
        row.setOpaque(false);
        row.setBorder(new EmptyBorder(0, Theme.px(8), 0, Theme.px(8)));
        row.add(metric("STATE", stateMetric));
        row.add(metric("VALIDATION", validationMetric));
        row.add(metric("ASSURANCE", assuranceMetric));
        row.add(metric("CONTROLS", controlsMetric));
        return row;
    }

    private JComponent metric(String label, JLabel value) {
        RoundedPanel card = new RoundedPanel(new BorderLayout(), Theme.SURFACE, Theme.BORDER_SOFT, Theme.px(10));
        card.setBorder(new EmptyBorder(Theme.px(10), Theme.px(12), Theme.px(10), Theme.px(12)));
        JLabel l = Theme.section(label);
        l.setForeground(Theme.FAINT);
        value.setFont(Theme.serif(18, Font.BOLD));
        value.setForeground(Theme.TEXT);
        card.add(l, BorderLayout.NORTH);
        card.add(value, BorderLayout.CENTER);
        return card;
    }

    private JComponent buildFooter() {
        JPanel footer = new JPanel(new BorderLayout());
        footer.setBackground(Theme.SURFACE);
        footer.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createMatteBorder(1, 0, 0, 0, Theme.BORDER_SOFT),
                new EmptyBorder(Theme.px(7), Theme.px(24), Theme.px(7), Theme.px(24))));
        JPanel left = new JPanel(new FlowLayout(FlowLayout.LEFT, Theme.px(8), 0));
        left.setOpaque(false);
        statusDot.setForeground(Theme.GREEN);
        statusDot.setFont(Theme.mono(10, Font.PLAIN));
        status.setFont(Theme.mono(10, Font.PLAIN));
        status.setForeground(Theme.MUTED);
        left.add(statusDot);
        left.add(status);
        footer.add(left, BorderLayout.WEST);
        JLabel right = new JLabel("VERIFICATION + VALIDATION  ·  NO PHYSICAL-MEDIA CLAIM");
        right.setFont(Theme.mono(9, Font.PLAIN));
        right.setForeground(Theme.MUTED);
        footer.add(right, BorderLayout.EAST);
        return footer;
    }

    private RoundedPanel card(String title) {
        RoundedPanel card = new RoundedPanel(new GridBagLayout(), Theme.SURFACE, Theme.BORDER_SOFT, Theme.px(12));
        card.setBorder(new EmptyBorder(Theme.px(12), Theme.px(14), Theme.px(12), Theme.px(14)));
        card.setAlignmentX(Component.LEFT_ALIGNMENT);
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, Integer.MAX_VALUE));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(0, 0, Theme.px(9), 0);
        c.fill = GridBagConstraints.HORIZONTAL;
        c.weightx = 1;
        c.gridx = 0;
        c.gridy = 0;
        JLabel head = Theme.section(title);
        head.setForeground(Theme.ACCENT);
        card.add(head, c);
        return card;
    }

    private void fit(RoundedPanel card) {
        card.setMaximumSize(new Dimension(Integer.MAX_VALUE, card.getPreferredSize().height));
    }

    private void addGroup(RoundedPanel card, int index, String label, JComponent field, Runnable browse) {
        JPanel group = new JPanel(new BorderLayout(0, Theme.px(4)));
        group.setOpaque(false);
        group.add(Theme.section(label), BorderLayout.NORTH);
        JPanel line = new JPanel(new BorderLayout(Theme.px(6), 0));
        line.setOpaque(false);
        if (field instanceof JTextField tf) tf.setFont(Theme.mono(12, Font.PLAIN));
        line.add(field, BorderLayout.CENTER);
        if (browse != null) {
            JButton b = new Theme.FlatButton("Browse", false);
            b.setPreferredSize(new Dimension(Theme.px(82), Theme.px(34)));
            b.addActionListener(e -> browse.run());
            line.add(b, BorderLayout.EAST);
        }
        group.add(line, BorderLayout.CENTER);
        add(group, card, index + 1);
    }

    private void add(JComponent child, RoundedPanel card, int row) {
        GridBagConstraints c = new GridBagConstraints();
        c.gridx = 0;
        c.gridy = row;
        c.weightx = 1;
        c.fill = GridBagConstraints.HORIZONTAL;
        c.insets = new Insets(0, 0, Theme.px(8), 0);
        card.add(child, c);
    }

    private JScrollPane scroll(JComponent c) {
        JScrollPane sp = new JScrollPane(c);
        sp.setBorder(null);
        sp.setBackground(Theme.FIELD);
        sp.getViewport().setBackground(Theme.FIELD);
        return sp;
    }

    private void browseTarget() {
        JFileChooser fc = new JFileChooser();
        fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            targetField.setText(fc.getSelectedFile().getAbsolutePath());
        }
    }

    private void browseWork() {
        JFileChooser fc = new JFileChooser();
        fc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            workField.setText(fc.getSelectedFile().getAbsolutePath());
        }
    }

    private void browseImage() {
        JFileChooser fc = new JFileChooser();
        fc.setFileSelectionMode(JFileChooser.FILES_ONLY);
        if (fc.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            imageField.setText(fc.getSelectedFile().getAbsolutePath());
        }
    }

    private String friendlyState(String state) {
        return switch (state) {
            case "COMMITTED" -> "Done";
            case "ABORTED" -> "Stopped";
            case "RESTORE_FAILED" -> "Needs help";
            case "UNRESOLVED" -> "Unclear";
            default -> "—";
        };
    }

    private String friendlyValidation(String validation) {
        return switch (validation) {
            case "PASS" -> "Checked";
            case "NOT_CHECKABLE" -> "Limited";
            case "FAIL" -> "Failed";
            case "RESTORE_FAILED" -> "Needs help";
            default -> "—";
        };
    }

    private String friendlyAssurance(String assurance) {
        return switch (assurance) {
            case "A2" -> "Standard";
            case "A1" -> "Basic";
            case "A0" -> "Minimal";
            default -> "—";
        };
    }

    private void doDestroy() {
        Path target = Path.of(targetField.getText().trim());
        Path work = Path.of(workField.getText().trim());
        Path image = imageField.getText().isBlank() ? null : Path.of(imageField.getText().trim());
        String canary = canaryField.getText().trim();
        Method method = modeBox.getSelectedIndex() == 0 ? Method.CRYPTO_SHRED : Method.OVERWRITE;
        long grace = ((Number) graceSpinner.getValue()).longValue();
        boolean require = requireBox.isSelected();

        if (!Files.isRegularFile(target)) {
            JOptionPane.showMessageDialog(this, "Choose an existing regular file.", "Input",
                    JOptionPane.WARNING_MESSAGE);
            return;
        }
        runAsync("Destroying " + target.getFileName() + "…",
                () -> AppService.destroy(target, method, work, image, canary, grace, require),
                v -> {
                    evidenceArea.setText(v.evidenceJson());
                    evidenceArea.setCaretPosition(0);
                    stateMetric.setText(friendlyState(v.state()));
                    validationMetric.setText(friendlyValidation(v.validation()));
                    assuranceMetric.setText(friendlyAssurance(v.assurance()));
                    controlsMetric.setText(v.checks().stream()
                            .anyMatch(x -> x.startsWith("positive control: FOUND")) ? "On" : "N/A");
                    logPane.append("");
                    logPane.append(v.message().sentence());
                    logPane.append("The Evidence JSON tab holds the technical record.");
                    tabs.setSelectedIndex(0);
                });
    }

    private void doVerify() {
        Path work = Path.of(workField.getText().trim());
        runAsync("Verifying evidence…", () -> AppService.verify(work), v -> {
            stateMetric.setText(v.valid() ? "VERIFIED" : "INVALID");
            validationMetric.setText(v.valid() ? "SIGNATURES OK" : "TAMPER");
            controlsMetric.setText(v.valid() ? "CHAIN OK" : "FAILED");
            logPane.append("verify: " + v.summary());
            for (String e : v.errors()) logPane.append("  error: " + e);
            if (!v.valid()) setStatus("Verification FAILED", Theme.RED);
        });
    }

    private void doRecover() {
        Path work = Path.of(workField.getText().trim());
        runAsync("Recovering…", () -> AppService.recover(work), v -> {
            for (String line : v.lines()) logPane.append(line);
        });
    }

    private void doSelfTest() {
        runAsync("Running control-validated memory test…", AppService::selfTest, v -> {
            stateMetric.setText("MEMORY");
            validationMetric.setText(v.result());
            assuranceMetric.setText("—");
            controlsMetric.setText(v.checks().stream()
                    .anyMatch(x -> x.startsWith("positive control: FOUND")) ? "VALID" : "INVALID");
            logPane.append("memory self-test: " + v.result());
            for (String check : v.checks()) logPane.append("  " + check);
        });
    }

    private <T> void runAsync(String label, Callable<T> task, Consumer<T> onDone) {
        setBusy(true);
        setStatus(label, Theme.AMBER);
        logPane.append("");
        logPane.append("== " + label + " ==");
        new SwingWorker<T, Void>() {
            @Override protected T doInBackground() throws Exception { return task.call(); }

            @Override protected void done() {
                try {
                    onDone.accept(get());
                    setStatus("Ready", Theme.GREEN);
                } catch (Exception e) {
                    Throwable cause = e.getCause() == null ? e : e.getCause();
                    logPane.append("ERROR: " + cause.getClass().getSimpleName() + ": " + cause.getMessage());
                    JOptionPane.showMessageDialog(MainFrame.this, cause.getMessage(),
                            "Operation failed", JOptionPane.ERROR_MESSAGE);
                    setStatus("Failed", Theme.RED);
                } finally {
                    setBusy(false);
                }
            }
        }.execute();
    }

    private void setBusy(boolean busy) {
        destroyBtn.setEnabled(!busy);
        verifyBtn.setEnabled(!busy);
        recoverBtn.setEnabled(!busy);
        testBtn.setEnabled(!busy);
    }

    private void setStatus(String text, Color color) {
        status.setText(text);
        statusDot.setForeground(color);
    }
}
