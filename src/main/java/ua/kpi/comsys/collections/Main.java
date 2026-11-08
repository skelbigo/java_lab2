package ua.kpi.comsys.collections;

import java.util.List;

public class Main {

    public static void main(String[] args) {
        LogAnalyzer analyzer = new LogAnalyzer();

        List<String> logLines = List.of(
                "127.0.0.1 - alice [01/May/2025:07:20:10 +0000] \"GET /index.html HTTP/1.1\" 200 9481",
                "192.168.1.10 - bob [01/May/2025:07:21:10 +0000] \"GET /home HTTP/1.1\" 200 1200",
                "127.0.0.1 - alice [01/May/2025:07:22:10 +0000] \"POST /login HTTP/1.1\" 200 500"
        );

        System.out.println("Unique IPs: " + analyzer.getUniqueIps(logLines));
        System.out.println("Top 2 IPs: " + analyzer.getTopIps(logLines, 2));
    }
}
