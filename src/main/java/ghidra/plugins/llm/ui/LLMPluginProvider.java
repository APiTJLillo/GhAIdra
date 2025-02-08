package ghidra.plugins.llm.ui;

import java.awt.*;
import java.awt.event.MouseEvent;
import javax.swing.*;

import docking.ActionContext;
import docking.ComponentProvider;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.Plugin;
import ghidra.plugins.llm.LLMAnalysisManager;
import ghidra.plugins.llm.ui.components.*;
import ghidra.plugins.llm.ui.operations.OperationManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;

public class LLMPluginProvider extends ComponentProvider {
    private volatile boolean disposed = false;
    private final JPanel mainPanel;
    private final Plugin plugin;
    private final LLMAnalysisManager analysisManager;
    private final OperationManager operationManager;
    private final AnalysisOptionsPanel optionsPanel;
    private final AnalysisOutputPanel outputPanel;
    private final OperationButtonPanel buttonPanel;
    private UpdateListener updateListener;

    public LLMPluginProvider(Plugin plugin, LLMAnalysisManager analysisManager) {
        super(plugin.getTool(), "LLM Analysis", plugin.getName());
        this.plugin = plugin;
        this.analysisManager = analysisManager;
        
        // Create components
        this.mainPanel = new JPanel(new BorderLayout(10, 10));
        this.mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        this.optionsPanel = new AnalysisOptionsPanel(analysisManager);
        this.outputPanel = new AnalysisOutputPanel();
        this.buttonPanel = new OperationButtonPanel();
        
        // Create operation manager
        this.operationManager = new OperationManager(
            analysisManager, optionsPanel, outputPanel, buttonPanel);
        
        // Build UI
        buildPanel();
        
        // Setup button actions
        setupActions();
    }

    public void addUpdateListener(UpdateListener listener) {
        this.updateListener = listener;
        this.outputPanel.setUpdateListener(listener);
    }

    private void buildPanel() {
        // Add options panel to west
        mainPanel.add(optionsPanel, BorderLayout.WEST);
        
        // Add output panel to center
        mainPanel.add(outputPanel, BorderLayout.CENTER);
        
        // Add button panel to south
        mainPanel.add(buttonPanel, BorderLayout.SOUTH);
    }

    private void setupActions() {
        buttonPanel.setAnalyzeActionListener(() -> analyzeCurrentFunction());
        buttonPanel.setAnalyzeAllActionListener(() -> analyzeAllFunctions());
        buttonPanel.setRenameFunctionActionListener(() -> suggestRenames(false));
        buttonPanel.setRenameAllActionListener(() -> suggestRenames(true));
        buttonPanel.setConfigureActionListener(() -> showConfigDialog());
        buttonPanel.setClearActionListener(() -> clearOutput());
    }

    public void showConfigDialog() {
        Frame parent = plugin.getTool().getToolFrame();
        LLMConfigDialog configDialog = new LLMConfigDialog(parent, true, plugin);
        configDialog.setLocationRelativeTo(parent);
        configDialog.setVisible(true);
    }

    public void analyzeCurrentFunction() {
        Function function = getCurrentFunction();
        if (function != null) {
            operationManager.displayAnalysisStart(function);
            analysisManager.analyzeFunction(function, 0)
                .thenAccept(result -> {
                    outputPanel.displayAnalysisResult(result, function.getName());
                    operationManager.handleAnalysisComplete();
                })
                .exceptionally(e -> {
                    operationManager.handleAnalysisError(e.getMessage());
                    return null;
                });
        }
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

    public void analyzeFunction(Function function) {
        if (function != null) {
            operationManager.displayAnalysisStart(function);
            analysisManager.analyzeFunction(function, 0)
                .thenAccept(result -> {
                    outputPanel.displayAnalysisResult(result, function.getName());
                })
                .exceptionally(e -> {
                    operationManager.handleAnalysisError(e.getMessage());
                    return null;
                });
        }
    }

    public void suggestRenamesForFunction(Function function) {
        if (function != null) {
            operationManager.displayRenameStart(function);
            analysisManager.suggestRenames(function, 0)
                .thenAccept(result -> {
                    if (result != null) {
                        appendOutput("Suggested function name: " + result.getFunctionName() + "\n\n");
                        if (result.getVariableNames() != null) {
                            appendOutput("Suggested variable names:\n");
                            result.getVariableNames().forEach((oldName, newName) -> 
                                appendOutput(String.format("  %s → %s\n", oldName, newName))
                            );
                        }
                    }
                    operationManager.handleAnalysisComplete();
                })
                .exceptionally(e -> {
                    operationManager.handleAnalysisError(e.getMessage());
                    return null;
                });
        }
    }

    private void suggestRenames(boolean includeVariables) {
        Function function = getCurrentFunction();
        if (function != null) {
            suggestRenamesForFunction(function);
        }
    }

    private Function getCurrentFunction() {
        if (!(plugin instanceof ProgramPlugin)) {
            Msg.showError(this, mainPanel, "Error", "Invalid plugin type");
            return null;
        }
        ProgramPlugin programPlugin = (ProgramPlugin)plugin;
        ProgramLocation location = programPlugin.getProgramLocation();
        if (location == null) {
            Msg.showError(this, mainPanel, "Error", "No location selected");
            return null;
        }

        Address address = location.getAddress();
        if (address == null) {
            Msg.showError(this, mainPanel, "Error", "Invalid address");
            return null;
        }

        Function function = programPlugin.getCurrentProgram()
            .getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            Msg.showError(this, mainPanel, "Error", "No function at current location");
            return null;
        }

        return function;
    }

    @Override
    public ActionContext getActionContext(MouseEvent event) {
        return null;
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    @Override
    public void componentHidden() {
        if (!disposed) {
            clearOutput();
        }
    }

    @Override
    public void componentShown() {
        // Reset operation state when component is shown
        operationManager.handleAnalysisComplete();
    }

    public synchronized void close() {
        disposed = true;
        operationManager.handleAnalysisComplete();
        clearOutput();
    }

    public synchronized boolean isDisposed() {
        return disposed;
    }

    // Output handling methods
    public void clearOutput() {
        if (updateListener != null) {
            updateListener.onUpdate();
        }
        outputPanel.clearOutput();
    }

    public void appendOutput(String text) {
        outputPanel.appendOutput(text);
    }

    public void setSummary(String text) {
        outputPanel.setSummary(text);
    }
}
