package io.jvd.file;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for what a destruction <em>reports</em>, as opposed to what it was asked to do.
 *
 * <p>The distinction matters because the whole point of this project is that the output
 * can be trusted. A result that reports the request rather than the outcome lets a
 * script believe a destruction succeeded when the file is still on disk.
 */
class FileDestroyerOutcomeTest {

    @Test
    void aSuccessfulDestructionReportsTheFileIsGone(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("victim.txt");
        Files.writeString(file, "sensitive content");

        FileDestroyer.Result r = FileDestroyer.destroy(file, 1, true);

        assertTrue(r.deleted(), "the file was deleted, so the result must say so");
        assertFalse(Files.exists(file), "and the file must actually be gone");
        assertEquals("sensitive content".length(), r.bytes());
        assertEquals(1, r.passes());
    }

    @Test
    void keepingTheFileReportsItWasNotDeleted(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("keepme.txt");
        Files.writeString(file, "sensitive content");

        FileDestroyer.Result r = FileDestroyer.destroy(file, 1, false);

        assertFalse(r.deleted(), "the file was kept, so the result must say so");
        assertTrue(Files.exists(file), "and the file must still be there");
    }

    @Test
    void deleteOnlyReportsWhetherTheFileIsReallyGone(@TempDir Path tmp) throws Exception {
        Path file = tmp.resolve("unlink.txt");
        Files.writeString(file, "sensitive content");

        FileDestroyer.Result r = FileDestroyer.deleteOnly(file);

        assertTrue(r.deleted(), "the unlink succeeded, so the result must say so");
        assertFalse(Files.exists(file));
    }

    @Test
    void anUnlinkThatCannotHappenIsReportedAsNotDeleted(@TempDir Path tmp) throws Exception {
        // The interesting case: the file is overwritten, but the unlink cannot be done
        // because the directory cannot be written to. The old code reported the
        // <em>request</em> to delete, so it claimed success while the file survived.
        Path dir = tmp.resolve("locked");
        Files.createDirectories(dir);
        Path file = dir.resolve("stuck.txt");
        Files.writeString(file, "sensitive content");

        // Remove write permission from the directory so the unlink cannot succeed.
        // setWritable does not work on a directory, so the POSIX permissions are used.
        java.util.Set<java.nio.file.attribute.PosixFilePermission> perms =
                java.nio.file.attribute.PosixFilePermissions.fromString("r-xr-xr-x");
        Files.setPosixFilePermissions(dir, perms);
        try {
            FileDestroyer.Result r = FileDestroyer.destroy(file, 1, true);
            if (Files.exists(file)) {
                assertFalse(r.deleted(),
                        "the file survived, so the result must not claim it was deleted");
            } else {
                // Some filesystems allow the unlink anyway; then the result is right.
                assertTrue(r.deleted());
            }
        } finally {
            Files.setPosixFilePermissions(dir,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rwxr-xr-x"));
        }
    }

    @Test
    void theResultNeverClaimsMoreThanItDid(@TempDir Path tmp) throws Exception {
        // The deleted flag must agree with the filesystem, always. There is no state in
        // which the flag says true and the file is still there.
        for (boolean delete : new boolean[]{true, false}) {
            Path file = tmp.resolve("check-" + delete + ".txt");
            Files.writeString(file, "content");
            FileDestroyer.Result r = FileDestroyer.destroy(file, 1, delete);
            assertEquals(!Files.exists(file), r.deleted(),
                    "the result must agree with what is on disk");
        }
    }
}
