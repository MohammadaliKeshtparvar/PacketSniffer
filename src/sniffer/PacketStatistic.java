package sniffer;

import java.util.ArrayList;
import java.util.HashMap;

public class PacketStatistic {
    public static int tcpCounter;
    public static int udpCounter;
    public static int icmpCounter;
    public static int totalPackets;
    public static int totalSize;
    public static ArrayList<SourceIP> ipCounters = new ArrayList<>();
    public static int fragmentPackets;
    public static int minSizePacket = 32;
    public static int maxSizePacket = 10000;
    public static double averageSizePacket;
    public static int httpCounter;
    public static int dnsCounter;
    public static int httpsCounter;
    public static int ftpCounter;
}
