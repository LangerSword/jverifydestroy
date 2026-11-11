package io.jvd.web;

/**
 * The page a visitor lands on at {@code GET /}.
 *
 * <p>It is a plain string constant rather than a resource file so that the service has
 * nothing to load at runtime and nothing to get wrong about classpath packaging. It is
 * self-contained by design: no stylesheet, no font, no script, no image, nothing fetched from
 * anywhere. A visitor who blocks every external request still gets a readable page, and the
 * service never leaks a request to a third party.</p>
 *
 * <p>The colours are the ones the desktop application uses, so the website and the tool look
 * like the same product.</p>
 */
public final class IndexPage {

    /** The background colour, matching the desktop application. */
    public static final String BACKGROUND = "#0B0D10";

    /** The text colour, matching the desktop application. */
    public static final String TEXT = "#ECE9E2";

    /** The accent colour, matching the desktop application. */
    public static final String ACCENT = "#C8F56A";

    /** The page itself. */
    public static final String HTML = """
            <!doctype html>
            <html lang="en">
            <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>jverifydestroy verification service</title>
            <style>
              :root {
                --bg: #0B0D10;
                --text: #ECE9E2;
                --accent: #C8F56A;
                --muted: #8A8F98;
                --line: #23262C;
              }
              * { box-sizing: border-box; }
              body {
                margin: 0;
                padding: 0;
                background: var(--bg);
                color: var(--text);
                font: 16px/1.65 ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto,
                      Helvetica, Arial, sans-serif;
              }
              main {
                max-width: 46rem;
                margin: 0 auto;
                padding: 3.5rem 1.25rem 4rem;
              }
              h1 {
                font-size: 1.9rem;
                line-height: 1.25;
                margin: 0 0 .5rem;
                letter-spacing: -.01em;
              }
              h2 {
                font-size: 1.05rem;
                margin: 2.5rem 0 .75rem;
                color: var(--accent);
                letter-spacing: .04em;
                text-transform: uppercase;
              }
              p { margin: 0 0 1rem; }
              .tagline { color: var(--muted); margin-bottom: 2rem; }
              code, pre {
                font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
                font-size: .875rem;
              }
              code { color: var(--accent); }
              pre {
                background: #12151A;
                border: 1px solid var(--line);
                border-radius: 8px;
                padding: 1rem;
                overflow-x: auto;
                margin: 0 0 1rem;
              }
              table { border-collapse: collapse; width: 100%; margin-bottom: 1rem; }
              th, td {
                text-align: left;
                padding: .55rem .75rem;
                border-bottom: 1px solid var(--line);
                vertical-align: top;
              }
              th { color: var(--muted); font-weight: 600; white-space: nowrap; }
              td code { color: var(--text); }
              ul { margin: 0 0 1rem; padding-left: 1.25rem; }
              li { margin-bottom: .4rem; }
              .note {
                border-left: 2px solid var(--accent);
                padding: .1rem 0 .1rem 1rem;
                color: var(--muted);
              }
              footer {
                margin-top: 3rem;
                padding-top: 1.5rem;
                border-top: 1px solid var(--line);
                color: var(--muted);
                font-size: .875rem;
              }
              a { color: var(--accent); }
            </style>
            </head>
            <body>
            <main>
              <h1>jverifydestroy verification service</h1>
              <p class="tagline">Check whether a destruction evidence log is authentic.</p>

              <p>When a tool destroys a file, it writes a receipt. That receipt is signed and
              kept in an append-only log, and a checkpoint is published describing the state
              of the log at that moment. This service takes those two documents and tells you
              whether they still agree with each other and with the signatures on them.</p>

              <p>It is a public checker. You can send it anything. It reads what you send,
              checks it, and tells you what it found. It never stores what you send and never
              asks for a path on your computer.</p>

              <h2>What a result means</h2>
              <ul>
                <li><code>valid: true</code> &mdash; the log matches its checkpoint and its
                    signatures. Nothing has been changed since it was written.</li>
                <li><code>valid: false</code> &mdash; the material was read successfully but it
                    does not agree with its own signatures. Something was edited, removed, or
                    reordered. This is a successful check with a bad answer, not a broken
                    service.</li>
              </ul>
              <p class="note">A tamper detection is a successful check. The service returns
                HTTP 200 with <code>valid: false</code> and a list of what it found. It only
                returns an HTTP error when it could not perform the check at all.</p>

              <h2>How to call it</h2>
              <p>Send a JSON object to <code>POST /verify</code>:</p>
              <pre>curl -s -X POST http://localhost:8080/verify \\
  -H 'Content-Type: application/json' \\
  -d '{
        "log": "{\\"seq\\":0,\\"leaf\\":\\"...\\",\\"record\\":{...}}",
        "checkpoint": "{\\"origin\\":\\"...\\",\\"size\\":1,...}",
        "logPublicKey": "base64 X.509 Ed25519 public key",
        "witnessPublicKey": "base64 X.509 Ed25519 public key"
      }'</pre>

              <table>
                <tr><th>Field</th><th>Required</th><th>What it is</th></tr>
                <tr><td><code>log</code></td><td>yes</td>
                    <td>The log as JSON Lines, one <code>{seq, leaf, record}</code> object per
                        line.</td></tr>
                <tr><td><code>checkpoint</code></td><td>yes</td>
                    <td>The checkpoint as a single JSON object.</td></tr>
                <tr><td><code>logPublicKey</code></td><td>yes</td>
                    <td>Base64 X.509 Ed25519 public key that signed the checkpoint.</td></tr>
                <tr><td><code>witnessPublicKey</code></td><td>no</td>
                    <td>Base64 X.509 Ed25519 public key of the co-signer. When supplied, the
                        witness co-signature is checked too.</td></tr>
                <tr><td><code>evidencePublicKey</code></td><td>no</td>
                    <td>Base64 X.509 Ed25519 public key that signed the individual records.
                        When supplied, each record's signature is checked too.</td></tr>
              </table>

              <p>The response is a JSON object with <code>valid</code>, <code>summary</code>,
                <code>errors</code>, <code>records</code>, <code>checkpointSize</code>,
                <code>witnessChecked</code> and <code>checkedAt</code>.</p>

              <h2>Other endpoints</h2>
              <table>
                <tr><th>Endpoint</th><th>What it returns</th></tr>
                <tr><td><code>GET /health</code></td>
                    <td>That the service is up, and the tool and version it speaks for.</td></tr>
                <tr><td><code>GET /schema</code></td>
                    <td>The JSON Schema that every evidence record is checked against.</td></tr>
              </table>

              <h2>What this cannot tell you</h2>
              <p>Destroying a file is a logical operation. The evidence records that fact
                honestly and also records, in every record, what it cannot promise: physical
                flash, firmware remapping, controller-held copies, backups, snapshots, and
                copies made before the tool ran are all out of reach. A <code>valid: true</code>
                answer means the receipt is authentic. It does not mean the disk is blank, and
                no response from this service should be read that way.</p>

              <footer>
                jverifydestroy 1.0.0 &mdash; a public evidence checker.
                The service holds no state between requests and stores nothing you send.
              </footer>
            </main>
            </body>
            </html>
            """;

    private IndexPage() {
    }
}
