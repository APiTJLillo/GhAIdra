package ghidra.plugins.azure;

import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.*;

import docking.ComponentProvider;
import ghidra.app.services.CodeViewerService;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;

public class AzurePluginProvider extends ComponentProvider {
    private final GhidraAzurePlugin plugin;
    private final JPanel mainPanel;
    private final JTextArea outputArea;
    private final JTabbedPane tabbedPane;

    public AzurePluginProvider(GhidraAzurePlugin plugin, String owner) {
        super(plugin.getTool(), "Azure AI Assistant", owner);
        this.plugin = plugin;

        mainPanel = new JPanel(new BorderLayout());
        tabbedPane = new JTabbedPane();
        
        JPanel analysisPanel = createAnalysisPanel();
        tabbedPane.addTab("Analysis", analysisPanel);
        
        JPanel settingsPanel = createSettingsPanel();
        tabbedPane.addTab("Settings", settingsPanel);

        outputArea = new JTextArea(10, 40);
        outputArea.setEditable(false);
        JScrollPane scrollPane = new JScrollPane(outputArea);
        
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        mainPanel.add(scrollPane, BorderLayout.SOUTH);
    }

    private JPanel createAnalysisPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridwidth = GridBagConstraints.REMAINDER;
        
        JButton findNameButton = new JButton("Find Best Function Name");
        findNameButton.addActionListener(e -> findBestFunctionName());
        panel.add(findNameButton, gbc);

        JButton explainButton = new JButton("Explain Function");
        explainButton.addActionListener(e -> explainFunction());
        panel.add(explainButton, gbc);

        JButton renameVarsButton = new JButton("Rename Variables");
        renameVarsButton.addActionListener(e -> renameVariables());
        panel.add(renameVarsButton, gbc);

        gbc.weighty = 1.0;
        panel.add(Box.createVerticalGlue(), gbc);

        return panel;
    }

    private JPanel createSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        // Settings components will be added here in future updates
        return panel;
    }

    private void findBestFunctionName() {
        appendOutput("Finding best function name...");
        CodeViewerService codeViewer = plugin.getTool().getService(CodeViewerService.class);
        if (codeViewer == null || codeViewer.getCurrentLocation() == null) {
            appendOutput("Error: Cannot determine current location");
            return;
        }
        
        Function function = plugin.getCurrentProgram()
            .getFunctionManager()
            .getFunctionContaining(codeViewer.getCurrentLocation().getAddress());
        
        if (function == null) {
            appendOutput("Error: No function found at current location");
            return;
        }

        // Create and execute task
        plugin.getTool().execute(new ghidra.util.task.Task("Finding Best Function Name", true, false, true) {
            @Override
            public void run(ghidra.util.task.TaskMonitor monitor) throws ghidra.util.exception.CancelledException {
                try {
                    String prompt = "Given this function details, suggest a clear and descriptive name that reflects its purpose:\n\n" + 
                                  plugin.getFunctionDetails(function);

                    String suggestion = plugin.analyzeWithAI(prompt);
                    // Update UI on EDT
                    javax.swing.SwingUtilities.invokeLater(() -> appendOutput(suggestion));
                } catch (Exception e) {
                    // Update UI on EDT
                    javax.swing.SwingUtilities.invokeLater(() -> appendOutput("Error: " + e.getMessage()));
                }
            }
        });
    }

    private void explainFunction() {
        appendOutput("Analyzing function...");
        CodeViewerService codeViewer = plugin.getTool().getService(CodeViewerService.class);
        if (codeViewer == null || codeViewer.getCurrentLocation() == null) {
            appendOutput("Error: Cannot determine current location");
            return;
        }
        
        Function function = plugin.getCurrentProgram()
            .getFunctionManager()
            .getFunctionContaining(codeViewer.getCurrentLocation().getAddress());
        
        if (function == null) {
            appendOutput("Error: No function found at current location");
            return;
        }

        // Create and execute task
        plugin.getTool().execute(new ghidra.util.task.Task("Analyzing Function", true, false, true) {
            @Override
            public void run(ghidra.util.task.TaskMonitor monitor) throws ghidra.util.exception.CancelledException {
                try {
                    plugin.analyzeCurrentFunction();
                    javax.swing.SwingUtilities.invokeLater(() -> 
                        appendOutput("Analysis complete. Check the function's comments in the listing."));
                } catch (Exception e) {
                    javax.swing.SwingUtilities.invokeLater(() -> 
                        appendOutput("Error: " + e.getMessage()));
                }
            }
        });
    }

    private void renameVariables() {
        appendOutput("Finding best variable names...");
        CodeViewerService codeViewer = plugin.getTool().getService(CodeViewerService.class);
        if (codeViewer == null || codeViewer.getCurrentLocation() == null) {
            appendOutput("Error: Cannot determine current location");
            return;
        }
        
        Function function = plugin.getCurrentProgram()
            .getFunctionManager()
            .getFunctionContaining(codeViewer.getCurrentLocation().getAddress());
        
        if (function == null) {
            appendOutput("Error: No function found at current location");
            return;
        }

        // Create and execute task
        plugin.getTool().execute(new ghidra.util.task.Task("Finding Best Variable Names", true, false, true) {
            @Override
            public void run(ghidra.util.task.TaskMonitor monitor) throws ghidra.util.exception.CancelledException {
                try {
                    String prompt = "Given this function details, suggest better names for any unclear or generic variable names to improve code readability:\n\n" + 
                                  plugin.getFunctionDetails(function);

                    String suggestions = plugin.analyzeWithAI(prompt);
                    javax.swing.SwingUtilities.invokeLater(() -> appendOutput(suggestions));
                } catch (Exception e) {
                    javax.swing.SwingUtilities.invokeLater(() -> appendOutput("Error: " + e.getMessage()));
                }
            }
        });
    }

    public void appendOutput(String text) {
        outputArea.append(text + "\n");
        outputArea.setCaretPosition(outputArea.getDocument().getLength());
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    public void updateLocation(ProgramLocation loc) {
        // Update provider state based on current location if needed
    }
}
