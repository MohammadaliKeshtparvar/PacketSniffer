package sniffer;

import jpcap.packet.*;
import jpcap.*;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;


public class SnifferFrame extends JFrame {

    private static JButton startButton;
    private static JButton saveButton;
    private static JButton stopButton;
    private static JButton schematicButton;
    private static JComboBox<String> filterOptions;
    private static final int DEFAULT_HEIGHT = 720;
    private static final int DEFAULT_WIDTH = DEFAULT_HEIGHT * 16 / 9;
    private JLabel filterLabel;
    private JLabel packetInfoLabel;
    private JLabel headerInformation;
    private JScrollPane jScrollPane1;
    private JScrollPane jScrollPane2;
    private JScrollPane scrollPacketTable;
    public static JTable packetTable;
    private static JTextArea jTextArea1;
    private JTextArea decimalInfoText;
    private JToolBar topToolBar;
    public static NetworkInterface[] NETWORK_INTERFACES;
    public static JpcapCaptor captureStatus;
    public CapturePacketThread capturePacketThread;
    public static int INDEX = 2;
    private boolean captureState = false;
    public static int packetNumber;
    List<Packet> packetList = new ArrayList<>();

    public SnifferFrame() {
        NETWORK_INTERFACES = JpcapCaptor.getDeviceList();
        setLayout(new BorderLayout());
        setPreferredSize(new Dimension(DEFAULT_WIDTH, DEFAULT_HEIGHT));
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLocation(350, 200);
        handleStartButton();
        handleStopButton();
        handleSaveButton();
        handleSchematicButton();
        handleFilterOptions();
        handleFilterLabel();
        handlePacketInfoLabel();
        handlePacketTable();
        initComponents();
        handleUIManager();
        setVisible(true);
    }

    public void handleStartButton() {
        startButton = new JButton("start");
        startButton.setOpaque(true);
        startButton.setFont(new Font("Dialog", 1, 13));
        startButton.setPreferredSize(new Dimension(100, 24));
        startButton.setFocusable(true);
        startButton.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent event) {
                startButtonActionPerformed(event);
            }
        });
    }

    public void handleStopButton() {
        stopButton = new JButton("Stop");
        stopButton.setOpaque(true);
        stopButton.setForeground(Color.RED);
        stopButton.setFont(new Font("Dialog", 1, 13));
        stopButton.setPreferredSize(new Dimension(100, 24));
        stopButton.addActionListener(new ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent e) {
                stopButtonActionPerformed(e);
            }
        });
    }

    public void handleSaveButton() {
        saveButton = new JButton("Save");
        saveButton.setOpaque(true);
        saveButton.setFont(new Font("Dailog", 1, 13));
        saveButton.setPreferredSize(new Dimension(100, 24));
        saveButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent evt) {
                saveButtonActionPerformed(evt);
            }
        });
    }

    public void handleSchematicButton() {
        schematicButton = new JButton("schematic");
        schematicButton.setPreferredSize(new Dimension(100, 24));
        schematicButton.setOpaque(true);
        schematicButton.setFont(new Font("Dialog", 1, 13));
        schematicButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                schematicButtonActionPerform(e);
            }
        });
    }

    public void schematicButtonActionPerform(ActionEvent e) {
        Schematic schematic = new Schematic(PacketStatistic.tcpCounter, PacketStatistic.udpCounter, PacketStatistic.icmpCounter);
    }

    public void handleFilterOptions() {
        filterOptions = new JComboBox<>();
        filterOptions.setModel(new DefaultComboBoxModel<>(new String[] { "---", "TCP", "UDP", "ICMP", "ARP"}));
        filterOptions.setOpaque(true);
        filterOptions.setPreferredSize(new java.awt.Dimension(320, 24));
    }

    public void handleFilterLabel() {
        filterLabel = new JLabel();
        filterLabel.setText("  FILTER  ");
        filterLabel.setOpaque(true);
        filterLabel.setBorder(BorderFactory.createLineBorder(Color.BLACK));
    }

    public void handlePacketInfoLabel() {
        packetInfoLabel = new JLabel();
        packetInfoLabel.setText("Packet information:");
        packetInfoLabel.setOpaque(true);
        packetInfoLabel.setMaximumSize(new Dimension(DEFAULT_WIDTH, 20));

    }

    public void CapturePackets() {
        capturePacketThread = new CapturePacketThread() {
            public Object construct() {
                try {
                    captureStatus = JpcapCaptor.openDevice(NETWORK_INTERFACES[INDEX], 65535, false, 20);
                    if (filterOptions.getSelectedItem().toString().equals("UDP")) {
                        captureStatus.setFilter("udp", true);
                    } else if (filterOptions.getSelectedItem().toString().equals("TCP")) {
                        captureStatus.setFilter("tcp", true);
                    } else if (filterOptions.getSelectedItem().toString().equals("ICMP")) {
                        captureStatus.setFilter("icmp", true);
                    } else if (filterOptions.getSelectedItem().toString().equals("ARP")) {
                        captureStatus.setFilter("arp", true);
                    }

                    while (captureState) {
                        captureStatus.processPacket(1, new PacketContents());
                        packetList.add(captureStatus.getPacket());
                    }
                    captureStatus.close();

                } catch (Exception e) {
                    e.printStackTrace();
                }
                return 0;
            }

            public void finished() {
                this.interrupt();
            }
        };
        capturePacketThread.start();
    }

    private void handlePacketTable() {
        packetTable = new JTable(){
            public boolean isCellEditable(int row, int column){
                return false;
            }
            @Override
            protected void createDefaultRenderers() {
                super.createDefaultRenderers();
            }
        };

        packetTable.setModel(new DefaultTableModel(new Object [][] {},
                new String [] {"Number.", "Length", "Source", "Destination", "Protocol", "SrcPort", "DstPort", "TTL"}) {
            Class[] types = new Class [] {
                    String.class, Object.class, Object.class, Object.class, String.class, String.class, String.class, String.class
            };

            public Class getColumnClass(int columnIndex) {
                return types [columnIndex];
            }
        });
        packetTable.setFocusable(true);
        packetTable.setRowHeight(30);
        packetTable.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                jTable1MouseClicked();
            }
        });
        packetTable.addKeyListener(new KeyListener() {
            @Override
            public void keyTyped(KeyEvent e) {
                jTable1MouseClicked();
            }

            @Override
            public void keyPressed(KeyEvent e) {
                jTable1MouseClicked();
            }

            @Override
            public void keyReleased(KeyEvent e) {
                jTable1MouseClicked();
            }
        });
    }

    public void initComponents() {
        topToolBar = new JToolBar();
        scrollPacketTable = new JScrollPane();

        jScrollPane1 = new JScrollPane();
        jTextArea1 = new JTextArea();
        jScrollPane2 = new JScrollPane();
        decimalInfoText = new JTextArea();

        headerInformation = new JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("AUT Packet Sniffer _ Computer Network");

        topToolBar.setRollover(true);

        JPanel topPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 0));
        topPanel.add(filterLabel);
        topPanel.add(filterOptions);
        topPanel.add(startButton);
        topPanel.add(stopButton);
        topPanel.add(saveButton);
        topPanel.add(schematicButton);
        topPanel.setOpaque(true);

        topToolBar.add(topPanel);

        scrollPacketTable.setViewportView(packetTable);

        jTextArea1.setEditable(false);
        jTextArea1.setColumns(38);
        jTextArea1.setRows(15);
        jTextArea1.setOpaque(true);
        jTextArea1.setFont(new Font("Dialog", 2, 14));
        jScrollPane1.setViewportView(jTextArea1);

        jScrollPane2.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);

        decimalInfoText.setEditable(false);
        decimalInfoText.setColumns(38);
        decimalInfoText.setRows(15);
        decimalInfoText.setFont(new Font("Dialog", 2, 14));
        jScrollPane2.setViewportView(decimalInfoText);

        headerInformation.setText("Header Information (Byte Array)");
        headerInformation.setOpaque(true);

        JPanel mainPanel = new JPanel(new BorderLayout());
        JPanel textPanelInfo = new JPanel(new BorderLayout());
        JPanel midPanel = new JPanel(new BorderLayout());
        midPanel.add(packetInfoLabel, BorderLayout.NORTH);
        midPanel.add(jScrollPane1, BorderLayout.CENTER);
        textPanelInfo.add(headerInformation, BorderLayout.NORTH);
        textPanelInfo.add(jScrollPane2, BorderLayout.CENTER);
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.add(midPanel, BorderLayout.NORTH);
        leftPanel.add(textPanelInfo, BorderLayout.SOUTH);
        mainPanel.add(topToolBar, BorderLayout.NORTH);
        mainPanel.add(scrollPacketTable, BorderLayout.CENTER);
        mainPanel.add(leftPanel, BorderLayout.EAST);
        add(mainPanel);

        pack();
    }

    private void jTable1MouseClicked() {
        Object obj = packetTable.getModel().getValueAt(packetTable.getSelectedRow(), 0);
        String set = PacketContents.receivedPackets.get((int) obj).toString().replace(" ", "\n");
        String dataLink = PacketContents.receivedPackets.get((int) obj).datalink.toString().replace(" ", "\n");
        IPPacket p = (IPPacket) PacketContents.receivedPackets.get((int) obj);
        jTextArea1.setText("Version: "+ p.version +"\n" + "More Fragment: "+p.more_frag+"\nDo not fragment: "+ p.dont_frag+"\nCapLen: "+p.caplen +
                "\nFlow label: " +p.flow_label  + "\nRSV_TOS:"+ p.rsv_tos+set +"\n\nDataLink: "+dataLink);
        StringBuilder s = new StringBuilder();
        int counter = 0;
        for (Byte b : PacketContents.receivedPackets.get((int) obj).header) {
            s.append(b);
            s.append(" ");
            counter++;
            if (counter % 7 == 0) {
                s.append("\n");
            }
        }
        StringBuilder dataString = new StringBuilder();
        int count = 0;
        for (Byte b : PacketContents.receivedPackets.get((int) obj).data) {
            dataString.append(b);
            dataString.append(" ");
            count++;
            if (count % 7 == 0) {
                dataString.append("\n");
            }
        }
        decimalInfoText.setText("Header Information :\n"+s.toString()+"\n\nData : \n"+dataString.toString());
    }

    private void startButtonActionPerformed(ActionEvent evt) {
        if (!captureState) {
            captureState = true;
            CapturePackets();
            saveButton.setEnabled(false);
            filterOptions.setEnabled(false);
        }
    }

    private void stopButtonActionPerformed(ActionEvent evt) {
        if (captureState) {
            captureState = false;
            capturePacketThread.finished();
            saveButton.setEnabled(true);
            filterOptions.setEnabled(true);
        }
    }

    private void saveButtonActionPerformed(java.awt.event.ActionEvent evt)  {
        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("HH_mm_ss");
        LocalDateTime now = LocalDateTime.now();
        FileWriter logFile = null;
        try {
            File file = new File(dtf.format(now)+".txt");
            logFile = new FileWriter(file);
            logFile.write("The number of TCP packets : ");
            logFile.write(PacketStatistic.tcpCounter+"");
            logFile.write("\n");
            logFile.write("The number of UDP packets : ");
            logFile.write(PacketStatistic.udpCounter+"");
            logFile.write("\n");
            logFile.write("The number of ICMP packets : ");
            logFile.write(PacketStatistic.icmpCounter+"");
            logFile.write("\n");
            logFile.write("The number of HTTPS packets : " + PacketStatistic.httpsCounter + "\n");
            logFile.write("The number of HTTP packets : " + PacketStatistic.httpCounter + "\n");
            logFile.write("The number of FTP packets : " + PacketStatistic.ftpCounter + "\n\n");
            logFile.write("Number of Fragment Packets : "+ PacketStatistic.fragmentPackets+ "\n");
            logFile.write("Minimum size : " + PacketStatistic.minSizePacket+"\n");
            logFile.write("Maximum size : " + PacketStatistic.maxSizePacket+"\n");
            logFile.write("Average size : " + PacketStatistic.averageSizePacket+"\n\n");
            sortedList(logFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            logFile.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void sortedList(FileWriter logFile) {
        Collections.sort(PacketStatistic.ipCounters);
        int counter = 1;
        for (SourceIP s : PacketStatistic.ipCounters) {
            try {
                logFile.write(counter+" ) " + s.getCounterIP() +" --> " + s.getSourceIP()+"\n");
                counter++;
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void handleUIManager() {
        UIManager.put("control", Color.DARK_GRAY.darker());
        UIManager.put("info", new Color(128,128,128));
        UIManager.put("nimbusBase", new Color( 18, 30, 49));
        UIManager.put("nimbusAlertYellow", new Color( 248, 187, 0));
        UIManager.put("nimbusDisabledText", new Color( 128, 128, 128));
        UIManager.put("nimbusFocus", new Color(115,164,209));
        UIManager.put("nimbusGreen", new Color(176,179,50));
        UIManager.put("nimbusInfoBlue", new Color( 66, 139, 221));
        UIManager.put("nimbusLightBackground", Color.DARK_GRAY);
        UIManager.put("nimbusOrange", new Color(191,98,4));
        UIManager.put("nimbusRed", new Color(169,46,34) );
        UIManager.put("nimbusSelectedText", new Color( 255, 255, 255));
        UIManager.put("nimbusSelectionBackground", new Color( 239, 123, 139));
        UIManager.put("text", new Color( 255, 251, 230));
    }
}
