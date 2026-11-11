package io.jvd.web;

import java.util.List;

/**
 * What one verification run found.
 *
 * <p>This is the whole answer in one immutable value: whether the evidence is authentic, what
 * went wrong if it is not, what was checked, and when. It is a record because a report is a
 * fact about the past and must not be edited after the fact.</p>
 *
 * @param valid           whether the log, the checkpoint, and the signatures all check out
 * @param outcome         the classification of the run
 * @param summary         one sentence a visitor can read without any jargon
 * @param errors          the specific problems found, empty when the run was clean
 * @param warnings        things that were not checked, stated so nobody assumes they were
 * @param records         the number of records the log contained
 * @param recordResults   what happened to each record in the log
 * @param checkpointSize  the size the checkpoint claims the log had
 * @param checkpointRoot  the base64 Merkle root the checkpoint commits to
 * @param witnessChecked  whether a witness co-signature was supplied and verified
 * @param checkedAt       when the check ran, ISO-8601
 */
public record VerificationReport(boolean valid,
                                  Outcome outcome,
                                  String summary,
                                  List<String> errors,
                                  List<String> warnings,
                                  int records,
                                  List<VerificationService.RecordResult> recordResults,
                                  long checkpointSize,
                                  String checkpointRoot,
                                  boolean witnessChecked,
                                  String checkedAt) {

    /**
     * Normalises the collections.
     *
     * <p>A record's constructor cannot enforce immutability of the lists it is handed, so the
     * lists are copied here and unmodifiable views are published. A caller that could mutate
     * the error list of a finished report could change what a visitor is told about evidence
     * that was already checked.</p>
     */
    public VerificationReport {
        errors = errors == null ? List.of() : List.copyOf(errors);
        warnings = warnings == null ? List.of() : List.copyOf(warnings);
        recordResults = recordResults == null ? List.of() : List.copyOf(recordResults);
        checkpointRoot = checkpointRoot == null ? "" : checkpointRoot;
        summary = summary == null ? "" : summary;
        checkedAt = checkedAt == null ? "" : checkedAt;
    }

    /**
     * The JSON body for this report, in the field order the API contract documents.
     *
     * <p>The field order is fixed here rather than left to the JSON writer so the published
     * contract matches the bytes on the wire exactly.</p>
     */
    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"valid\":").append(valid).append(',');
        sb.append("\"outcome\":\"").append(outcome.name()).append("\",");
        sb.append("\"summary\":\"").append(escape(summary)).append("\",");
        sb.append("\"errors\":").append(array(errors)).append(',');
        sb.append("\"warnings\":").append(array(warnings)).append(',');
        sb.append("\"records\":").append(records).append(',');
        sb.append("\"recordResults\":").append(recordResultsJson()).append(',');
        sb.append("\"checkpointSize\":").append(checkpointSize).append(',');
        sb.append("\"checkpointRoot\":\"").append(escape(checkpointRoot)).append("\",");
        sb.append("\"witnessChecked\":").append(witnessChecked).append(',');
        sb.append("\"checkedAt\":\"").append(escape(checkedAt)).append('"');
        sb.append('}');
        return sb.toString();
    }

    /** The per-record results as a JSON array, in log order. */
    private String recordResultsJson() {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < recordResults.size(); i++) {
            VerificationService.RecordResult r = recordResults.get(i);
            if (i > 0) sb.append(',');
            sb.append("{\"seq\":").append(r.seq())
                    .append(",\"eventId\":\"").append(escape(r.eventId())).append('"')
                    .append(",\"eventType\":\"").append(escape(r.eventType())).append('"')
                    .append(",\"status\":\"").append(r.status().name()).append('"')
                    .append(",\"problems\":").append(array(r.problems()))
                    .append('}');
        }
        return sb.append(']').toString();
    }

    private static String array(List<String> values) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < values.size(); i++) {
            if (i > 0) sb.append(',');
            sb.append('"').append(escape(values.get(i))).append('"');
        }
        return sb.append(']').toString();
    }

    /** Escapes a string for the JSON body. Only the characters JSON requires are escaped. */
    private static String escape(String s) {
        StringBuilder sb = new StringBuilder(s.length() + 16);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                case '\n' -> sb.append("\\n");
                case '\r' -> sb.append("\\r");
                case '\t' -> sb.append("\\t");
                case '\b' -> sb.append("\\b");
                case '\f' -> sb.append("\\f");
                default -> {
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
                }
            }
        }
        return sb.toString();
    }
}
