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
            "Crypto-shred (recommended)", "Overwrite (NIST Clear; weak on flash)"});
    private final JSpinner graceSpinner = new JSpinner(new SpinnerNumberModel(0, 0, 86_400, 1));
    private final JCheckBox requireBox = new JCheckBox("Require raw-media validation (roll back if NOT_CHECKABLE)");
    private final JTextArea logArea = new JTextArea();
    private final JTextArea evidenceArea = new JTextArea();
    private final JTabbedPane tabs = new JTabbedPane();
    private final JLabel status = new JLabel("Ready");
    private final JButton destroyBtn = new JButton("Destroy");
    private final JButton verifyBtn = new JButton("Verify evidence");
    private final JButton recoverBtn = new JButton("Recover");
    private final JButton testBtn = new JButton("Memory self-test");

    public MainFrame() {
        super("jVerifyDestroy — verifiable logical destruction");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(980, 620));

        workField.setText(Path.of(System.getProperty("user.home"), ".jvd-work").toString());
        logArea.setEditable(false);
        logArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        evidenceArea.setEditable(false);
        evidenceArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        tabs.addTab("Log", new JScrollPane(logArea));
        tabs.addTab("Evidence JSON", new JScrollPane(evidenceArea));

        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(new EmptyBorder(12, 12, 12, 12));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(4, 4, 4, 4);
        c.fill = GridBagConstraints.HORIZONTAL;
        int y = 0;

        y = row(form, c, y, "File to destroy", targetField, this::browseTarget);
        y = row(form, c, y, "Work directory", workField, this::browseWork);
        c.gridx = 0; c.gridy = y++; c.weightx = 0; c.gridwidth = 1;
        form.add(new JLabel("Method"), c);
        c.gridx = 1; c.weightx = 1; form.add(modeBox, c);
        c.gridx = 2; c.weightx = 0; form.add(new JLabel(""), c);
        y = row(form, c, y, "Raw image (optional)", imageField, this::browseImage);
        y = row(form, c, y, "Canary hex (optional)", canaryField, null);

        c.gridx = 0; c.gridy = y++; c.weightx = 0; c.gridwidth = 1;
        form.add(new JLabel("Grace (seconds)"), c);
        c.gridx = 1; c.weightx = 1; form.add(graceSpinner, c);
        c.gridx = 2; c.weightx = 0; form.add(new JLabel(""), c);

        c.gridx = 0; c.gridy = y++; c.gridwidth = 3; c.weightx = 1;
        form.add(requireBox, c);

        JPanel buttons = new JPanel(new GridLayout(2, 2, 8, 8));
        buttons.setBorder(new EmptyBorder(0, 12, 12, 12));
        buttons.add(destroyBtn);
        buttons.add(verifyBtn);
        buttons.add(recoverBtn);
        buttons.add(testBtn);
        destroyBtn.setToolTipText("Destroy the file and commit the evidence");
        verifyBtn.setToolTipText("Check the log, checkpoint, witness, and record signatures offline");
        recoverBtn.setToolTipText("Restore a transaction that crashed before COMMIT");
        testBtn.setToolTipText("Run one control-validated memory wipe and scan a child JVM");

        JPanel left = new JPanel(new BorderLayout());
        JScrollPane formScroll = new JScrollPane(form);
        formScroll.setBorder(null);
        left.add(formScroll, BorderLayout.CENTER);
        left.add(buttons, BorderLayout.SOUTH);
        left.setPreferredSize(new Dimension(520, 620));

        JSplitPane split = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, left, tabs);
        split.setResizeWeight(0.42);
        add(split, BorderLayout.CENTER);
        status.setBorder(new EmptyBorder(4, 10, 4, 10));
        add(status, BorderLayout.SOUTH);

        destroyBtn.addActionListener(e -> doDestroy());
        verifyBtn.addActionListener(e -> doVerify());
        recoverBtn.addActionListener(e -> doRecover());
        testBtn.addActionListener(e -> doSelfTest());

        append("Ready. Select a file and a work directory, then Destroy.");
        append("The work directory holds keys, journal, vault, and checkpoints.");
        append("A COMMITTED transaction cannot be restored; that is the guarantee.");
        pack();
        setLocationRelativeTo(null);
    }

    private int row(JPanel form, GridBagConstraints c, int y, String label, JTextField field, Runnable browse) {
        c.gridx = 0; c.gridy = y; c.weightx = 0; c.gridwidth = 1;
        form.add(new JLabel(label), c);
        c.gridx = 1; c.weightx = 1; form.add(field, c);
        c.gridx = 2; c.weightx = 0;
        JButton b = new JButton("Browse…");
        b.setEnabled(browse != null);
        if (browse != null) b.addActionListener(e -> browse.run());
        form.add(b, c);
        return y + 1;
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

    private void doDestroy() {
        Path target = Path.of(targetField.getText().trim());
        Path work = Path.of(workField.getText().trim());
        Path image = imageField.getText().isBlank() ? null : Path.of(imageField.getText().trim());
        String canary = canaryField.getText().trim();
        Method method = modeBox.getSelectedIndex() == 0 ? Method.CRYPTO_SHRED : Method.OVERWRITE;
        long grace = ((Number) graceSpinner.getValue()).longValue();
        boolean require = requireBox.isSelected();

        if (!Files.isRegularFile(target)) {
            JOptionPane.showMessageDialog(this, "Choose an existing regular file.", "Input", JOptionPane.WARNING_MESSAGE);
            return;
        }
        runAsync("Destroying " + target.getFileName() + "…", () -> AppService.destroy(target, method, work, image, canary, grace, require),
                v -> {
                    evidenceArea.setText(v.evidenceJson());
                    append("state=" + v.state() + "  validation=" + v.validation()
                            + "  dataAbsent=" + v.dataAbsent() + "  restored=" + v.restored());
                    append("assurance=" + v.assurance());
                    for (String check : v.checks()) append("  check: " + check);
                    append("journal=" + v.journal());
                    append("checkpoint=" + v.checkpoint());
                    append("detail=" + v.detail());
                    if ("COMMITTED".equals(v.state())) {
                        append("COMMITTED: the key/vault is gone; restore is impossible by design.");
                    } else {
                        append("ABORTED: original restored=" + v.restored() + ". Review the checks above.");
                    }
                });
    }

    private void doVerify() {
        Path work = Path.of(workField.getText().trim());
        runAsync("Verifying evidence…", () -> AppService.verify(work), v -> {
            append("verify: " + v.summary());
            for (String e : v.errors()) append("  error: " + e);
            if (!v.valid()) status.setText("Verification FAILED");
        });
    }

    private void doRecover() {
        Path work = Path.of(workField.getText().trim());
        runAsync("Recovering…", () -> AppService.recover(work), v -> {
            for (String line : v.lines()) append(line);
        });
    }

    private void doSelfTest() {
        runAsync("Running control-validated memory test…", AppService::selfTest, v -> {
            append("memory self-test: " + v.result());
            for (String check : v.checks()) append("  " + check);
        });
    }

    private <T> void runAsync(String label, Callable<T> task, Consumer<T> onDone) {
        setBusy(true);
        status.setText(label);
        append("== " + label + " ==");
        new SwingWorker<T, Void>() {
            @Override protected T doInBackground() throws Exception { return task.call(); }

            @Override protected void done() {
                try {
                    onDone.accept(get());
                    status.setText("Ready");
                } catch (Exception e) {
                    Throwable cause = e.getCause() == null ? e : e.getCause();
                    append("ERROR: " + cause.getClass().getSimpleName() + ": " + cause.getMessage());
                    JOptionPane.showMessageDialog(MainFrame.this, cause.getMessage(),
                            "Operation failed", JOptionPane.ERROR_MESSAGE);
                    status.setText("Failed");
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

    private void append(String line) {
        logArea.append(line + "\n");
        logArea.setCaretPosition(logArea.getDocument().getLength());
    }
}
