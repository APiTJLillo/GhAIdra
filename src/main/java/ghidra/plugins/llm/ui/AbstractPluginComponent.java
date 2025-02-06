package ghidra.plugins.llm.ui;

import java.awt.*;
import javax.swing.*;
import java.awt.event.*;

import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginTool;

public abstract class AbstractPluginComponent {
    private final Plugin plugin;
    private final String windowTitle;
    private final JFrame frame;
    private final JPanel mainPanel;

    protected AbstractPluginComponent(Plugin plugin, String windowTitle) {
        this.plugin = plugin;
        this.windowTitle = windowTitle;
        this.mainPanel = new JPanel(new BorderLayout());
        this.frame = createFrame();
    }

    private JFrame createFrame() {
        PluginTool tool = plugin.getTool();
        JFrame frame = new JFrame(windowTitle);
        frame.setIconImage(tool.getToolFrame().getIconImage());
        frame.setContentPane(mainPanel);
        frame.setDefaultCloseOperation(JFrame.HIDE_ON_CLOSE);
        frame.setSize(800, 600);
        frame.setLocationRelativeTo(tool.getToolFrame());

        // Add help button
        JButton helpButton = new JButton("Help");
        helpButton.addActionListener(e -> showHelp());
        JPanel topButtonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        topButtonPanel.add(helpButton);

        // Keep existing NORTH component if any
        Component existingNorth = ((BorderLayout) mainPanel.getLayout()).getLayoutComponent(BorderLayout.NORTH);
        if (existingNorth != null) {
            JPanel northPanel = new JPanel(new BorderLayout());
            northPanel.add(existingNorth, BorderLayout.CENTER);
            northPanel.add(topButtonPanel, BorderLayout.EAST);
            mainPanel.add(northPanel, BorderLayout.NORTH);
        } else {
            mainPanel.add(topButtonPanel, BorderLayout.NORTH);
        }

        return frame;
    }

    protected void showHelp() {
        // Placeholder for help functionality
        JOptionPane.showMessageDialog(frame, "Help content is not available.", "Help", JOptionPane.INFORMATION_MESSAGE);
    }

    protected JPanel getMainPanel() {
        return mainPanel;
    }

    protected Plugin getPlugin() {
        return plugin;
    }

    protected PluginTool getTool() {
        return plugin.getTool();
    }

    public void show() {
        frame.setVisible(true);
        frame.toFront();
    }

    public void hide() {
        frame.setVisible(false);
    }

    public boolean isVisible() {
        return frame.isVisible();
    }

    public void dispose() {
        frame.dispose();
    }

    public Window getWindow() {
        return frame;
    }
}
