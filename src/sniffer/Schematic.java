package sniffer;

import javax.swing.*;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PiePlot3D;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.data.general.PieDataset;
import org.jfree.util.Rotation;

import java.awt.*;


public class Schematic extends JFrame {

    private static final long serialVersionUID = 1L;
    private int tcpCount;
    private int udpCount;
    private int icmpCount;

    public Schematic(int tcpCount, int udpCount, int icmpCount) {
        super(" Graphical Representation");
        this.tcpCount = tcpCount;
        this.udpCount = udpCount;
        this.icmpCount = icmpCount;
        PieDataset dataset = createDataset();
        JFreeChart chart = createChart(dataset, "Transmission Layer");
        ChartPanel chartPanel = new ChartPanel(chart);
        chartPanel.setPreferredSize(new Dimension(800, 500));
        setContentPane(chartPanel);
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setLocation(300, 200);
        pack();
        setVisible(true);

    }

    private PieDataset createDataset() {
        DefaultPieDataset result = new DefaultPieDataset();
        result.setValue("TCP", tcpCount);
        result.setValue("UDP", udpCount);
        result.setValue("ICMP", icmpCount);
        return result;
    }

    private JFreeChart createChart(PieDataset dataset, String title) {

        JFreeChart chart = ChartFactory.createPieChart3D(
                title,                  // chart title
                dataset,                // data
                true,                   // include legend
                true,
                false
        );

        PiePlot3D plot = (PiePlot3D) chart.getPlot();
        plot.setStartAngle(290);
        plot.setDirection(Rotation.CLOCKWISE);
        plot.setForegroundAlpha(0.5f);
        return chart;

    }
}