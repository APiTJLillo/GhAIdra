package ghidra.plugins.llm.ui.components;

import javax.swing.*;
import java.awt.*;
import ghidra.plugins.llm.ui.operations.OperationManager;

/**
 * Main tabbed interface containing analysis and simulation tabs.
 */
public class MainTabbedPanel extends JPanel {
    private final JTabbedPane tabbedPane;
    private final AnalysisOptionsPanel analysisOptionsPanel;
    private final SimulationConfigPanel simulationConfigPanel;
    private final AnalysisOutputPanel outputPanel;
    private final OperationButtonPanel buttonPanel;

    public MainTabbedPanel(OperationManager operationManager) {
        setLayout(new BorderLayout());

        // Create tabbed pane
        tabbedPane = new JTabbedPane();

        // Get panels from operation manager
        this.analysisOptionsPanel = operationManager.getAnalysisOptionsPanel();
        this.simulationConfigPanel = operationManager.getSimulationConfigPanel();
        this.outputPanel = operationManager.getOutputPanel();
        this.buttonPanel = operationManager.getButtonPanel();

        // Create Analysis Tab
        JPanel analysisTab = createAnalysisTab();
        tabbedPane.addTab("Analysis", null, analysisTab, "LLM Analysis Settings");

        // Create Simulation Tab
        JPanel simulationTab = createSimulationTab();
        tabbedPane.addTab("Simulation", null, simulationTab, "PCODE Simulation Settings");

        // Create main split layout
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setDividerLocation(0.4); // 40% for options, 60% for output
        splitPane.setResizeWeight(0.4); // Maintain the ratio when resizing
        
        // Add tabbed pane to left side
        splitPane.setLeftComponent(tabbedPane);
        
        // Create output panel wrapper
        JPanel outputWrapper = new JPanel(new BorderLayout());
        outputWrapper.setBorder(BorderFactory.createTitledBorder("Output"));
        outputWrapper.add(outputPanel, BorderLayout.CENTER);
        
        // Add output panel to right side
        splitPane.setRightComponent(outputWrapper);
        
        // Add split pane and buttons
        add(splitPane, BorderLayout.CENTER);
        add(buttonPanel, BorderLayout.SOUTH);

        // Add tab change listener
        tabbedPane.addChangeListener(e -> updateButtonVisibility());
        
        // Initial button visibility update
        updateButtonVisibility();
    }

    private JPanel createAnalysisTab() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        panel.add(analysisOptionsPanel, BorderLayout.CENTER);
        return panel;
    }

    private JPanel createSimulationTab() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        panel.add(simulationConfigPanel, BorderLayout.CENTER);
        return panel;
    }


    private void updateButtonVisibility() {
        int selectedIndex = tabbedPane.getSelectedIndex();
        String selectedTab = tabbedPane.getTitleAt(selectedIndex);
        
        // Show/hide buttons based on selected tab
        if ("Analysis".equals(selectedTab)) {
            buttonPanel.showAnalysisButtons();
        } else if ("Simulation".equals(selectedTab)) {
            buttonPanel.showSimulationButtons();
        }
    }

    public JTabbedPane getTabbedPane() {
        return tabbedPane;
    }
}
