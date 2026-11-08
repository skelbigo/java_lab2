package ua.kpi.comsys.collections;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;
import java.util.Set;

import static ua.kpi.comsys.collections.LogAnalyzerTest.TestResources.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class LogAnalyzerTest {

    private final LogAnalyzer analyzer = new LogAnalyzer();

    @Test
    void shouldReturnUniqueIps() {
        Set<String> actual = analyzer.getUniqueIps(LOGS);

        assertEquals(EXPECTED_UNIQUE_IPS, actual);
    }

    @Test
    void shouldReturnTopIpsByFrequency() {
        List<String> actual = analyzer.getTopIps(LOGS, 2);

        assertEquals(EXPECTED_TOP_TWO, actual);
    }

    @Test
    void shouldSortEqualFrequenciesLexicographically() {
        List<String> actual = analyzer.getTopIps(EQUAL_FREQUENCY_LOGS, 3);

        assertEquals(EXPECTED_TIE_ORDER, actual);
    }

    @Test
    void shouldReturnAllIpsWhenTopNExceedsCount() {
        List<String> actual = analyzer.getTopIps(LOGS, 10);

        assertEquals(EXPECTED_ALL_SORTED, actual);
    }

    @Test
    void shouldReturnEmptyCollectionsForEmptyLogs() {
        assertEquals(Set.of(), analyzer.getUniqueIps(List.of()));
        assertEquals(List.of(), analyzer.getTopIps(List.of(), 3));
    }

    @Test
    void shouldIgnoreMalformedLogLines() {
        Set<String> actual = analyzer.getUniqueIps(LOGS_WITH_INVALID_LINES);

        assertEquals(Set.of(IP_A), actual);
    }

    @Test
    void shouldIgnoreNullLogEntries() {
        List<String> logs = Arrays.asList(LOG_A, null);

        assertEquals(Set.of(IP_A), analyzer.getUniqueIps(logs));
    }

    @Test
    void shouldSupportIpv6Addresses() {
        assertEquals(
                Set.of("::1"),
                analyzer.getUniqueIps(List.of(IPV6_LOG))
        );
    }

    @Test
    void shouldRejectNullLogsForUniqueIps() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> analyzer.getUniqueIps(null)
        );

        assertEquals(NULL_LOGS_MESSAGE, exception.getMessage());
    }

    @Test
    void shouldRejectNullLogsForTopIps() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> analyzer.getTopIps(null, 2)
        );

        assertEquals(NULL_LOGS_MESSAGE, exception.getMessage());
    }

    @Test
    void shouldRejectNonPositiveTopN() {
        assertThrows(
                IllegalArgumentException.class,
                () -> analyzer.getTopIps(LOGS, 0)
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> analyzer.getTopIps(LOGS, -1)
        );
    }

    static class TestResources {

        static String IP_A = "127.0.0.1";
        static String IP_B = "192.168.1.10";
        static String IP_C = "10.0.0.5";

        static String NULL_LOGS_MESSAGE =
                "logLines cannot be null";

        static String LOG_A =
                "127.0.0.1 - alice [01/May/2025:07:20:10 +0000] \"GET /index.html HTTP/1.1\" 200 9481";

        static String LOG_B =
                "192.168.1.10 - bob [01/May/2025:07:21:10 +0000] \"GET /home HTTP/1.1\" 200 1200";

        static String LOG_A_REPEAT =
                "127.0.0.1 - alice [01/May/2025:07:22:10 +0000] \"POST /login HTTP/1.1\" 200 500";

        static String LOG_C =
                "10.0.0.5 - admin [01/May/2025:07:23:10 +0000] \"GET /admin HTTP/1.1\" 200 300";

        static String IPV6_LOG =
                "::1 - alice [01/May/2025:07:24:10 +0000] \"GET / HTTP/1.1\" 200 100";

        static String INVALID_LOG = "invalid log line";

        static String INVALID_IP_LOG =
                "999.999.999.999 - bob [01/May/2025:07:25:10 +0000] \"GET / HTTP/1.1\" 200 100";

        static List<String> LOGS =
                List.of(LOG_A, LOG_B, LOG_A_REPEAT, LOG_C);

        static List<String> EQUAL_FREQUENCY_LOGS =
                List.of(LOG_A, LOG_B, LOG_C);

        static List<String> LOGS_WITH_INVALID_LINES =
                List.of(LOG_A, INVALID_LOG, INVALID_IP_LOG);

        static Set<String> EXPECTED_UNIQUE_IPS =
                Set.of(IP_A, IP_B, IP_C);

        static List<String> EXPECTED_TOP_TWO =
                List.of(IP_A, IP_C);

        static List<String> EXPECTED_TIE_ORDER =
                List.of(IP_C, IP_A, IP_B);

        static List<String> EXPECTED_ALL_SORTED =
                List.of(IP_A, IP_C, IP_B);
    }
}
