package ua.kpi.comsys.collections;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LogAnalyzer {

    private static final Pattern LOG_PATTERN = Pattern.compile(
            "^(?<ip>\\S+)\\s+\\S+\\s+\\S+\\s+" +
                    "\\[\\d{2}/[A-Za-z]{3}/\\d{4}:\\d{2}:\\d{2}:\\d{2} [+-]\\d{4}\\]\\s+" +
                    "\"(?:[A-Z]+\\s+\\S+\\s+HTTP/\\d+(?:\\.\\d+)?|-)\"\\s+" +
                    "\\d{3}\\s+(?:\\d+|-)$"
    );

    public Set<String> getUniqueIps(List<String> logLines) {
        return new LinkedHashSet<>(countIps(logLines).keySet());
    }

    public List<String> getTopIps(List<String> logLines, int topN) {
        Map<String, Integer> counts = countIps(logLines);

        if (topN <= 0) {
            throw new IllegalArgumentException(
                    "topN must be greater than 0"
            );
        }

        return counts.entrySet().stream()
                .sorted(
                        Comparator.<Map.Entry<String, Integer>>comparingInt(Map.Entry::getValue)
                                .reversed()
                                .thenComparing(Map.Entry::getKey)
                )
                .limit(topN)
                .map(Map.Entry::getKey)
                .toList();
    }

    private Map<String, Integer> countIps(List<String> logLines) {
        if (logLines == null) {
            throw new IllegalArgumentException(
                    "logLines cannot be null"
            );
        }

        Map<String, Integer> counts = new LinkedHashMap<>();

        for (String line : logLines) {
            String ip = extractIp(line);

            if (ip != null) {
                counts.merge(ip, 1, Integer::sum);
            }
        }

        return counts;
    }

    private String extractIp(String line) {
        if (line == null) {
            return null;
        }

        Matcher matcher = LOG_PATTERN.matcher(line);

        if (!matcher.matches()) {
            return null;
        }

        String ip = matcher.group("ip");

        return isValidIp(ip) ? ip : null;
    }

    private boolean isValidIp(String ip) {
        if (ip.contains(":")) {
            if (!ip.matches("[0-9a-fA-F:.]+")) {
                return false;
            }

            try {
                return InetAddress.getByName(ip) instanceof Inet6Address;
            } catch (UnknownHostException e) {
                return false;
            }
        }

        String[] octets = ip.split("\\.", -1);

        if (octets.length != 4) {
            return false;
        }

        for (String octet : octets) {
            if (octet.isEmpty()
                    || octet.length() > 3
                    || !octet.matches("\\d+")) {
                return false;
            }

            if (Integer.parseInt(octet) > 255) {
                return false;
            }
        }

        return true;
    }
}
