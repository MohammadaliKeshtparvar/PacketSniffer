package sniffer;

import jpcap.PacketReceiver;
import jpcap.packet.Packet;
import javax.swing.table.DefaultTableModel;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;
import jpcap.packet.*;

import java.util.*;

import jpcap.packet.ICMPPacket;
import jpcap.packet.ARPPacket;
import jpcap.JpcapCaptor.*;
import jpcap.packet.Packet;
import jpcap.packet.EthernetPacket;
import jpcap.packet.DatalinkPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.IPv6Option;
import org.pcap4j.packet.IpPacket;
import org.pcap4j.packet.IpV4Packet;

public class PacketContents implements PacketReceiver {

    public static ArrayList<Object[]> rowList = new ArrayList<>();
    public static ArrayList<Packet> receivedPackets = new ArrayList<>();

    @Override
    public void receivePacket(Packet packet) {

        if (packet instanceof TCPPacket) {
            TCPPacket tcpPacket = (TCPPacket) packet;
//            for (Byte b : tcpPacket.header) {
//                System.out.print(b+" ");
//            }
//            System.out.println();
//            System.out.println("len: "+tcpPacket.len);
//            System.out.println("length: "+tcpPacket.length);
//            System.out.println("ident: "+tcpPacket.ident);
//            System.out.println("flow Label: "+tcpPacket.flow_label);
            if (((TCPPacket) packet).dst_port == 80) {
                PacketStatistic.httpCounter++;
                Object[] row = {SnifferFrame.packetNumber, tcpPacket.length, tcpPacket.src_ip, tcpPacket.dst_ip, "HTTP", tcpPacket.src_port, tcpPacket.dst_port, tcpPacket.hop_limit};
                rowList.add(new Object[]{SnifferFrame.packetNumber,  tcpPacket.length, tcpPacket.src_ip, tcpPacket.dst_ip, "HTTP", tcpPacket.src_port, tcpPacket.dst_port,
                    tcpPacket.ack, tcpPacket.ack_num, tcpPacket.data, tcpPacket.sequence, tcpPacket.offset, tcpPacket.header, tcpPacket.window});
                DefaultTableModel model = (DefaultTableModel) SnifferFrame.packetTable.getModel();
                model.addRow(row);
            }else if (((TCPPacket) packet).dst_port == 443) {
                PacketStatistic.httpsCounter++;
                Object[] row = {SnifferFrame.packetNumber, tcpPacket.length, tcpPacket.src_ip, tcpPacket.dst_ip, "HTTPS", tcpPacket.src_port, tcpPacket.dst_port, tcpPacket.hop_limit};

                rowList.add(new Object[]{SnifferFrame.packetNumber, tcpPacket.length, tcpPacket.src_ip, tcpPacket.dst_ip, "HTTPS", tcpPacket.src_port, tcpPacket.dst_port,
                    tcpPacket.ack, tcpPacket.ack_num, tcpPacket.data, tcpPacket.sequence, tcpPacket.offset, tcpPacket.header});
                DefaultTableModel model = (DefaultTableModel) SnifferFrame.packetTable.getModel();
                model.addRow(row);
            }else if (((TCPPacket) packet).dst_port == 21) {
                PacketStatistic.ftpCounter++;
                Object[] row = {SnifferFrame.packetNumber, tcpPacket.length, tcpPacket.src_ip, tcpPacket.dst_ip, "FTP", tcpPacket.src_port, tcpPacket.dst_port, tcpPacket.hop_limit};

                rowList.add(new Object[]{SnifferFrame.packetNumber, tcpPacket.length, tcpPacket.src_ip, tcpPacket.dst_ip, "FTP", tcpPacket.src_port, tcpPacket.dst_port,
                        tcpPacket.ack, tcpPacket.ack_num, tcpPacket.data, tcpPacket.sequence, tcpPacket.offset, tcpPacket.header});
                DefaultTableModel model = (DefaultTableModel) SnifferFrame.packetTable.getModel();
                model.addRow(row);

            } else {
                Object[] row = {SnifferFrame.packetNumber,  tcpPacket.length, tcpPacket.src_ip, tcpPacket.dst_ip, "TCP", tcpPacket.src_port, tcpPacket.dst_port, tcpPacket.hop_limit};

                rowList.add(new Object[]{SnifferFrame.packetNumber,  tcpPacket.length, tcpPacket.src_ip, tcpPacket.dst_ip, "TCP", tcpPacket.src_port, tcpPacket.dst_port,
                        tcpPacket.ack, tcpPacket.ack_num, tcpPacket.data, tcpPacket.sequence, tcpPacket.offset, tcpPacket.header});
                DefaultTableModel model = (DefaultTableModel) SnifferFrame.packetTable.getModel();
                model.addRow(row);
        }

            PacketStatistic.tcpCounter++;
            SnifferFrame.packetNumber++;
            PacketStatistic.totalPackets++;

            if (isNew(tcpPacket.src_ip.toString())) {
                SourceIP newSourceIP = new SourceIP(tcpPacket.src_ip.toString(), 1);
                PacketStatistic.ipCounters.add(newSourceIP);
            }

            if (PacketStatistic.minSizePacket > tcpPacket.length) {
                PacketStatistic.minSizePacket = tcpPacket.length;
            }

            if (PacketStatistic.maxSizePacket < tcpPacket.length) {
                PacketStatistic.maxSizePacket = tcpPacket.length;
            }

            if (PacketStatistic.totalPackets == 1) {
                PacketStatistic.minSizePacket = tcpPacket.length;
                PacketStatistic.maxSizePacket = tcpPacket.length;
                PacketStatistic.averageSizePacket = (double) tcpPacket.length;
            }else {
                PacketStatistic.averageSizePacket += tcpPacket.length;
                PacketStatistic.averageSizePacket /= 2;
            }
            receivedPackets.add(tcpPacket);
            if (tcpPacket.offset == 1) {
                PacketStatistic.fragmentPackets++;
            }

        } else if (packet instanceof UDPPacket) {
            PacketStatistic.udpCounter++;
            UDPPacket udpPacket = (UDPPacket) packet;
            if (udpPacket.dst_port == 53) {
                PacketStatistic.dnsCounter++;
                Object[] row = {SnifferFrame.packetNumber, udpPacket.length, udpPacket.src_ip, udpPacket.dst_ip, "DNS", udpPacket.src_port, udpPacket.dst_port};
                rowList.add(new Object[]{SnifferFrame.packetNumber, udpPacket.length, udpPacket.src_ip, udpPacket.dst_ip, "DNS", udpPacket.src_port, udpPacket.dst_port,
                        udpPacket.data, udpPacket.offset, udpPacket.header});

                DefaultTableModel model = (DefaultTableModel) SnifferFrame.packetTable.getModel();
                model.addRow(row);
            } else {
                Object[] row = {SnifferFrame.packetNumber, udpPacket.length, udpPacket.src_ip, udpPacket.dst_ip, "UDP", udpPacket.src_port, udpPacket.dst_port};
                rowList.add(new Object[]{SnifferFrame.packetNumber, udpPacket.length, udpPacket.src_ip, udpPacket.dst_ip, "UDP", udpPacket.src_port, udpPacket.dst_port,
                        udpPacket.data, udpPacket.offset, udpPacket.header});

                DefaultTableModel model = (DefaultTableModel) SnifferFrame.packetTable.getModel();
                model.addRow(row);
            }

            SnifferFrame.packetNumber++;
            PacketStatistic.totalPackets++;

            if (isNew(udpPacket.src_ip.toString())) {
                SourceIP newSourceIP = new SourceIP(udpPacket.src_ip.toString(), 1);
                PacketStatistic.ipCounters.add(newSourceIP);
            }

            if (PacketStatistic.minSizePacket > udpPacket.length) {
                PacketStatistic.minSizePacket = udpPacket.length;
            }

            if (PacketStatistic.maxSizePacket < udpPacket.length) {
                PacketStatistic.maxSizePacket = udpPacket.length;
            }

            if (PacketStatistic.totalPackets == 1) {
                PacketStatistic.minSizePacket = udpPacket.length;
                PacketStatistic.maxSizePacket = udpPacket.length;
                PacketStatistic.averageSizePacket = (double) udpPacket.length;
            }else {
                PacketStatistic.averageSizePacket += udpPacket.length;
                PacketStatistic.averageSizePacket /= 2;
            }
            receivedPackets.add(udpPacket);
            if (udpPacket.offset == 1) {
                PacketStatistic.fragmentPackets++;
            }

        } else if (packet instanceof ICMPPacket) {
            PacketStatistic.icmpCounter++;
            ICMPPacket icmpPacket = (ICMPPacket) packet;
            Object[] row = {SnifferFrame.packetNumber, icmpPacket.length, icmpPacket.src_ip, icmpPacket.dst_ip, "ICMP", "", "", icmpPacket.hop_limit};
            rowList.add(new Object[]{SnifferFrame.packetNumber, icmpPacket.length, icmpPacket.src_ip, icmpPacket.dst_ip, "ICMP", icmpPacket.checksum, icmpPacket.header,
                icmpPacket.offset, icmpPacket.orig_timestamp, icmpPacket.recv_timestamp, icmpPacket.trans_timestamp, icmpPacket.data});
            DefaultTableModel model = (DefaultTableModel) SnifferFrame.packetTable.getModel();
            model.addRow(row);
            SnifferFrame.packetNumber++;

            if (isNew(icmpPacket.src_ip.toString())) {
                SourceIP newSourceIP = new SourceIP(icmpPacket.src_ip.toString(), 1);
                PacketStatistic.ipCounters.add(newSourceIP);
            }

            PacketStatistic.totalPackets++;

            if (PacketStatistic.minSizePacket > icmpPacket.length) {
                PacketStatistic.minSizePacket = icmpPacket.length;
            }

            if (PacketStatistic.maxSizePacket < icmpPacket.length) {
                PacketStatistic.maxSizePacket = icmpPacket.length;
            }

            if (PacketStatistic.totalPackets == 1) {
                PacketStatistic.averageSizePacket = (double) icmpPacket.length;
            }else {
                PacketStatistic.averageSizePacket += icmpPacket.length;
                PacketStatistic.averageSizePacket /= 2;
            }
            receivedPackets.add(icmpPacket);

            if (icmpPacket.offset == 1) {
                PacketStatistic.fragmentPackets++;
            }
        }
    }

    private boolean isNew(String source) {
        for (SourceIP s : PacketStatistic.ipCounters) {
            if (s.getSourceIP().equals(source)) {
                s.setCounterIP(s.getCounterIP() + 1);
                return false;
            }
        }
        return true;
    }
}
