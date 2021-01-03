package sniffer;

import org.jetbrains.annotations.NotNull;

public class SourceIP implements Comparable{
    private String sourceIP;
    private int counterIP;

    public SourceIP(String sourceIP, int counterIP) {
        this.sourceIP = sourceIP;
        this.counterIP = counterIP;
    }

    public String getSourceIP() {
        return sourceIP;
    }

    public void setSourceIP(String sourceIP) {
        this.sourceIP = sourceIP;
    }

    public int getCounterIP() {
        return counterIP;
    }

    public void setCounterIP(int counterIP) {
        this.counterIP = counterIP;
    }

    @Override
    public int compareTo(@NotNull Object o) {
        int compare = ((SourceIP) o).getCounterIP();
        return this.counterIP - compare;
    }
}
