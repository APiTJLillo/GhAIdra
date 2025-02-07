package ghidra.plugins.llm.ui;

import java.awt.*;
import java.awt.event.MouseEvent;
import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.Plugin;
import ghidra.plugins.llm.AnalysisConfig;
import ghidra.plugins.llm.LLMAnalysisManager;
import ghidra.plugins.llm.FunctionSummaryResponse;
import ghidra.plugins.llm.RenamingResponse;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

public class LLMPluginProvider extends ComponentProvider {
    private final JTextArea outputArea;
    private final JTextArea summaryArea;
    private final LLMAnalysisManager analysisManager;
    private final JPanel mainPanel;
    private UpdateListener updateListener;
    private final String title;
    private final Plugin plugin;

    public LLMPluginProvider(Plugin plugin, LLMAnalysisManager analysisManager) {
        super(plugin.getTool(), "LLM Analysis", plugin.getName());
        this.plugin = plugin;
        this.analysisManager = analysisManager;
        this.outputArea = new JTextArea();
        this.summaryArea = new JTextArea();
        this.mainPanel = new JPanel(new BorderLayout());
        this.title = "LLM Analysis";
        
        buildPanel();
    }

    public void addUpdateListener(UpdateListener listener) {
        this.updateListener = listener;
    }

    @Override
    public String getTitle() {
        return title;
    }

    @Override
    public String getName() {
        return title;
    }

    @Override
    public ActionContext getActionContext(MouseEvent event) {
        return null;
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    private void buildPanel() {
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // Center split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        
        // Output area for detailed analysis
        outputArea.setEditable(false);
        outputArea.setWrapStyleWord(true);
        outputArea.setLineWrap(true);
        JScrollPane outputScroll = new JScrollPane(outputArea);
        outputScroll.setBorder(BorderFactory.createTitledBorder("Detailed Analysis"));
        splitPane.setTopComponent(outputScroll);
        
        // Summary area
        summaryArea.setEditable(false);
        summaryArea.setWrapStyleWord(true);
        summaryArea.setLineWrap(true);
        JScrollPane summaryScroll = new JScrollPane(summaryArea);
        summaryScroll.setBorder(BorderFactory.createTitledBorder("Function Summary"));
        splitPane.setBottomComponent(summaryScroll);
        
        splitPane.setResizeWeight(0.7);
        mainPanel.add(splitPane, BorderLayout.CENTER);
        
        // Analysis Options Panel
        JPanel optionsPanel = new JPanel();
        optionsPanel.setLayout(new BoxLayout(optionsPanel, BoxLayout.Y_AXIS));
        optionsPanel.setBorder(BorderFactory.createTitledBorder("Analysis Options"));

        JCheckBox recursiveAnalysisBox = new JCheckBox("Enable Recursive Analysis");
        recursiveAnalysisBox.addActionListener(e -> {
            analysisManager.setConfig(new AnalysisConfig());
            analysisManager.getConfig().setRecursiveAnalysis(recursiveAnalysisBox.isSelected());
        });
        
        JCheckBox recursiveRenamingBox = new JCheckBox("Enable Recursive Renaming");
        recursiveRenamingBox.addActionListener(e -> {
            if (analysisManager.getConfig() == null) {
                analysisManager.setConfig(new AnalysisConfig());
            }
            analysisManager.getConfig().setRecursiveRenaming(recursiveRenamingBox.isSelected());
        });

        JCheckBox renameSimilarBox = new JCheckBox("Automatically Rename Similar Functions");
        renameSimilarBox.addActionListener(e -> {
            if (analysisManager.getConfig() == null) {
                analysisManager.setConfig(new AnalysisConfig());
            }
            analysisManager.getConfig().setRenameSimilarFunctions(renameSimilarBox.isSelected());
        });

        // Align checkboxes to the left
        recursiveAnalysisBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        recursiveRenamingBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        renameSimilarBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        optionsPanel.add(recursiveAnalysisBox);
        optionsPanel.add(Box.createVerticalStrut(5));
        optionsPanel.add(recursiveRenamingBox);
        optionsPanel.add(Box.createVerticalStrut(5));
        optionsPanel.add(renameSimilarBox);
        
        mainPanel.add(optionsPanel, BorderLayout.WEST);

        // Buttons Panel
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new BoxLayout(buttonPanel, BoxLayout.Y_AXIS));
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // Function Analysis Section
        JPanel analysisButtons = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));
        JButton analyzeButton = new JButton("Analyze Function");
        JButton analyzeAllButton = new JButton("Analyze All Functions");
        analyzeButton.addActionListener(e -> analyzeCurrentFunction());
        analyzeAllButton.addActionListener(e -> analyzeAllFunctions());
        analysisButtons.add(analyzeButton);
        analysisButtons.add(analyzeAllButton);
        
        // Renaming Section
        JPanel renameButtons = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));
        JButton renameFunctionButton = new JButton("Rename Function");
        JButton renameAllButton = new JButton("Rename Function & Variables");
        renameFunctionButton.addActionListener(e -> suggestRenameFunction());
        renameAllButton.addActionListener(e -> suggestRenamesForCurrentFunction());
        renameButtons.add(renameFunctionButton);
        renameButtons.add(renameAllButton);

        // Utility Buttons Section
        JPanel utilityButtons = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));
        JButton configureButton = new JButton("Configure LLM");
        JButton clearButton = new JButton("Clear Output");
        configureButton.addActionListener(e -> showConfigDialog());
        clearButton.addActionListener(e -> clearOutput());
        utilityButtons.add(configureButton);
        utilityButtons.add(clearButton);

        // Add all button sections
        buttonPanel.add(analysisButtons);
        buttonPanel.add(Box.createVerticalStrut(5));
        buttonPanel.add(renameButtons);
        buttonPanel.add(Box.createVerticalStrut(5));
        buttonPanel.add(utilityButtons);
        
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);
    }

    private void showConfigDialog() {
        Frame parent = plugin.getTool().getToolFrame();
        LLMConfigDialog configDialog = new LLMConfigDialog(parent, true, plugin);
        configDialog.setLocationRelativeTo(parent);
        configDialog.setVisible(true);
    }

    public void analyzeFunction(Function function) {
        if (function == null) {
            Msg.showError(this, mainPanel, "Error", "No function selected");
            return;
        }

        clearOutput();
        appendOutput("Analyzing function: " + function.getName() + "\n");
        appendOutput("This may take a few minutes. You'll see the response stream as it arrives.\n");
        appendOutput("----------------------------------------\n");

        analysisManager.resetSession();
        analysisManager.analyzeFunction(function, 0)
            .thenAccept(result -> {
                if (result != null) {
                    setSummary(result.getSummary());
                    appendOutput("Function Summary: " + result.getSummary() + "\n\n");
                    
                    FunctionSummaryResponse.Details details = result.getDetails();
                    if (details != null) {
                        appendOutput("Purpose: " + details.getPurpose() + "\n\n");
                        appendOutput("Algorithmic Patterns: " + details.getAlgorithmicPatterns() + "\n\n");
                        appendOutput("Security Implications: " + details.getSecurityImplications() + "\n");
                    }
                    appendOutput("\n----------------------------------------\n");
                    appendOutput("Analysis complete for: " + function.getName() + "\n");
                } else {
                    appendOutput("Error: Failed to analyze function\n");
                }
            })
            .exceptionally(e -> {
                appendOutput("\nError during analysis: " + e.getMessage() + "\n");
                return null;
            });
    }

    public void suggestRenamesForFunction(Function function) {
        if (function == null) {
            Msg.showError(this, mainPanel, "Error", "No function selected");
            return;
        }

        clearOutput();
        appendOutput("Generating rename suggestions for: " + function.getName() + "\n");
        appendOutput("----------------------------------------\n");

        analysisManager.resetSession();
        analysisManager.suggestRenames(function, 0)
            .thenAccept(result -> {
                if (result != null) {
                    appendOutput("Suggested function name: " + result.getFunctionName() + "\n\n");
                    if (result.getVariableNames() != null && !result.getVariableNames().isEmpty()) {
                        appendOutput("Suggested variable names:\n");
                        result.getVariableNames().forEach((oldName, newName) -> 
                            appendOutput(String.format("  %s → %s\n", oldName, newName))
                        );
                    }
                    appendOutput("\n----------------------------------------\n");
                    appendOutput("Suggestions complete for: " + function.getName() + "\n");
                } else {
                    appendOutput("Error: Failed to generate suggestions\n");
                }
            })
            .exceptionally(e -> {
                appendOutput("\nError generating suggestions: " + e.getMessage() + "\n");
                return null;
            });
    }

    public void appendOutput(String text) {
        SwingUtilities.invokeLater(() -> {
            outputArea.append(text);
            outputArea.setCaretPosition(outputArea.getDocument().getLength());
        });
    }

    public void setSummary(String text) {
        SwingUtilities.invokeLater(() -> {
            summaryArea.setText(text);
            summaryArea.setCaretPosition(0);
        });
    }

    public void clearOutput() {
        SwingUtilities.invokeLater(() -> {
            outputArea.setText("");
            summaryArea.setText("");
            if (updateListener != null) {
                updateListener.onUpdate();
            }
        });
    }

    public void analyzeCurrentFunction() {
        if (!(plugin instanceof ProgramPlugin)) {
            Msg.showError(this, mainPanel, "Error", "Invalid plugin type");
            return;
        }
        ProgramPlugin programPlugin = (ProgramPlugin)plugin;
        Program program = programPlugin.getCurrentProgram();
        if (program == null) {
            Msg.showError(this, mainPanel, "Error", "No program is loaded");
            return;
        }
        
        ProgramLocation location = programPlugin.getProgramLocation();
        if (location == null) {
            Msg.showError(this, mainPanel, "Error", "No location selected");
            return;
        }

        Address address = location.getAddress();
        if (address == null) {
            Msg.showError(this, mainPanel, "Error", "Invalid address");
            return;
        }

        Function function = programPlugin.getCurrentProgram()
            .getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            Msg.showError(this, mainPanel, "Error", "No function at current location");
            return;
        }

        analyzeFunction(function);
    }
    
    public void analyzeAllFunctions() {
        if (!(plugin instanceof ProgramPlugin)) {
            Msg.showError(this, mainPanel, "Error", "Invalid plugin type");
            return;
        }
        ProgramPlugin programPlugin = (ProgramPlugin)plugin;
        Program program = programPlugin.getCurrentProgram();
        if (program == null) {
            Msg.showError(this, mainPanel, "Error", "No program is loaded");
            return;
        }

        clearOutput();
        appendOutput("Analyzing all functions...\n");

        program.getFunctionManager().getFunctions(true).forEach(function -> {
            if (!isDisposed()) {
                analyzeFunction(function);
            }
        });
    }
    
    public void suggestRenameFunction() {
        if (!(plugin instanceof ProgramPlugin)) {
            Msg.showError(this, mainPanel, "Error", "Invalid plugin type");
            return;
        }
        ProgramPlugin programPlugin = (ProgramPlugin)plugin;
        ProgramLocation location = programPlugin.getProgramLocation();
        if (location == null) {
            Msg.showError(this, mainPanel, "Error", "No location selected");
            return;
        }

        Address address = location.getAddress();
        if (address == null) {
            Msg.showError(this, mainPanel, "Error", "Invalid address");
            return;
        }

        Function function = programPlugin.getCurrentProgram()
            .getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            Msg.showError(this, mainPanel, "Error", "No function at current location");
            return;
        }

        suggestRenamesForFunction(function);
    }
    
    public void suggestRenamesForCurrentFunction() {
        suggestRenameFunction();
    }

    public boolean isDisposed() {
        return false;
    }

    @Override
    public void componentHidden() {
        if (!isDisposed()) {
            clearOutput();
        }
    }

    @Override
    public void componentShown() {
        // Nothing to do
    }
}
