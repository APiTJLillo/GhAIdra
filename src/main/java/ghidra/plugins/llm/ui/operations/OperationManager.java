package ghidra.plugins.llm.ui.operations;

import ghidra.plugins.llm.LLMAnalysisManager;
import ghidra.plugins.llm.ui.components.AnalysisOptionsPanel;
import ghidra.plugins.llm.ui.components.AnalysisOutputPanel;
import ghidra.plugins.llm.ui.components.OperationButtonPanel;
import ghidra.program.model.listing.Function;
import ghidra.util.Msg;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Manages operation state and coordinates between UI components.
 */
public class OperationManager {
    private final LLMAnalysisManager analysisManager;
    private final AnalysisOptionsPanel optionsPanel;
    private final AnalysisOutputPanel outputPanel;
    private final OperationButtonPanel buttonPanel;
    private final AtomicBoolean operationInProgress;

    public OperationManager(
            LLMAnalysisManager analysisManager,
            AnalysisOptionsPanel optionsPanel,
            AnalysisOutputPanel outputPanel,
            OperationButtonPanel buttonPanel) {
        this.analysisManager = analysisManager;
        this.optionsPanel = optionsPanel;
        this.outputPanel = outputPanel;
        this.buttonPanel = buttonPanel;
        this.operationInProgress = new AtomicBoolean(false);
        
        setupButtonHandlers();
    }

    private void setupButtonHandlers() {
        buttonPanel.setAnalyzeActionListener(() -> startAnalyzeOperation(false));
        buttonPanel.setAnalyzeAllActionListener(() -> startAnalyzeOperation(true));
        buttonPanel.setRenameFunctionActionListener(() -> startRenameOperation(false));
        buttonPanel.setRenameAllActionListener(() -> startRenameOperation(true));
        buttonPanel.setClearActionListener(this::clearOutput);
    }

    private synchronized void startOperation() {
        if (operationInProgress.get()) {
            Msg.showWarn(this, null, "Operation in Progress", 
                "Please wait for the current operation to complete.");
            return;
        }
        operationInProgress.set(true);
        buttonPanel.startOperation();
        optionsPanel.setEnabled(false);
    }

    private synchronized void finishOperation() {
        operationInProgress.set(false);
        buttonPanel.finishOperation();
        optionsPanel.setEnabled(true);
    }

    public void startAnalyzeOperation(boolean analyzeAll) {
        startOperation();
        try {
            optionsPanel.saveState();
            // Actual analysis would be triggered here by the caller
        } catch (Exception e) {
            outputPanel.displayError("Failed to start analysis: " + e.getMessage());
            finishOperation();
        }
    }

    public void startRenameOperation(boolean renameAll) {
        startOperation();
        try {
            optionsPanel.saveState();
            // Actual rename operation would be triggered here by the caller
        } catch (Exception e) {
            outputPanel.displayError("Failed to start renaming: " + e.getMessage());
            finishOperation();
        }
    }

    public void clearOutput() {
        outputPanel.clearOutput();
    }

    public void handleAnalysisComplete() {
        finishOperation();
    }

    public void handleAnalysisError(String error) {
        outputPanel.displayError(error);
        finishOperation();
    }

    public boolean isOperationInProgress() {
        return operationInProgress.get();
    }

    public void displayAnalysisStart(Function function) {
        outputPanel.startAnalysis(function.getName());
    }

    public void displayRenameStart(Function function) {
        outputPanel.startRenaming(function.getName());
    }
}
