package ghidra.plugins.llm.ui.operations;

import ghidra.plugins.llm.LLMAnalysisManager;
import ghidra.plugins.llm.ui.components.AnalysisOptionsPanel;
import ghidra.plugins.llm.ui.components.AnalysisOutputPanel;
import ghidra.plugins.llm.ui.components.OperationButtonPanel;
import ghidra.plugins.llm.ui.components.SimulationConfigPanel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.ArrayList;
import java.util.List;

/**
 * Manages operation state and coordinates between UI components.
 */
public class OperationManager {
    private final LLMAnalysisManager analysisManager;
    private final AnalysisOptionsPanel analysisOptionsPanel;
    private final AnalysisOutputPanel outputPanel;
    private final OperationButtonPanel buttonPanel;
    private final SimulationOperation simulationOperation;
    private final SimulationConfigPanel simulationConfigPanel;
    private final AtomicBoolean operationInProgress;

    public OperationManager(
            LLMAnalysisManager analysisManager,
            AnalysisOptionsPanel optionsPanel,
            AnalysisOutputPanel outputPanel,
            OperationButtonPanel buttonPanel,
            Program program) {
        this.analysisManager = analysisManager;
        this.analysisOptionsPanel = optionsPanel;
        this.outputPanel = outputPanel;
        this.buttonPanel = buttonPanel;
        this.operationInProgress = new AtomicBoolean(false);
        this.simulationOperation = new SimulationOperation(program);
        this.simulationConfigPanel = new SimulationConfigPanel(this::handleSimulationConfigChange);
        
        setupButtonHandlers();
    }

    private void handleSimulationConfigChange(java.util.Map<String, Object> newConfig) {
        // Handle simulation configuration changes if needed
    }

    private void setupButtonHandlers() {
        buttonPanel.setAnalyzeActionListener(() -> startAnalyzeOperation(false));
        buttonPanel.setAnalyzeAllActionListener(() -> startAnalyzeOperation(true));
        buttonPanel.setRenameFunctionActionListener(() -> startRenameOperation(false));
        buttonPanel.setRenameAllActionListener(() -> startRenameOperation(true));
        buttonPanel.setSimulateActionListener(this::startSimulateOperation);
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
        analysisOptionsPanel.setEnabled(false);
    }

    private synchronized void finishOperation() {
        operationInProgress.set(false);
        buttonPanel.finishOperation();
        analysisOptionsPanel.setEnabled(true);
    }

    public void startAnalyzeOperation(boolean analyzeAll) {
        startOperation();
        try {
            analysisOptionsPanel.saveState();
            Function currentFunction = analysisManager.getCurrentFunction();
            if (currentFunction == null) {
                outputPanel.displayError("No function selected");
                finishOperation();
                return;
            }

            if (!analyzeAll) {
                outputPanel.startAnalysis(currentFunction.getName());
                analysisManager.analyzeFunction(currentFunction, 0)
                    .thenAccept(result -> {
                        outputPanel.displayAnalysisResult(result, currentFunction.getName());
                        handleAnalysisComplete();
                    })
                    .exceptionally(e -> {
                        handleAnalysisError(e.getMessage());
                        return null;
                    });
            } else {
                // Get all functions and count them
                Program program = currentFunction.getProgram();
                List<Function> allFunctions = new ArrayList<>();
                program.getFunctionManager().getFunctions(true).forEach(allFunctions::add);
                
                // Start batch analysis with total count
                outputPanel.startBatchAnalysis(allFunctions.size());
                AtomicInteger completed = new AtomicInteger(0);
                List<java.util.concurrent.CompletableFuture<Void>> futures = new ArrayList<>();
                
                allFunctions.forEach(function -> {
                    futures.add(analysisManager.analyzeFunction(function, 0)
                        .thenAccept(result -> {
                            outputPanel.displayAnalysisResult(result, function.getName());
                            outputPanel.updateBatchProgress(completed.incrementAndGet(), allFunctions.size());
                        })
                        .exceptionally(e -> {
                            handleAnalysisError("Error analyzing " + function.getName() + ": " + e.getMessage());
                            return null;
                        }));
                });
                
                // Wait for all analyses to complete
                java.util.concurrent.CompletableFuture.allOf(futures.toArray(new java.util.concurrent.CompletableFuture[0]))
                    .thenRun(this::handleAnalysisComplete)
                    .exceptionally(e -> {
                        handleAnalysisError("Error during batch analysis: " + e.getMessage());
                        return null;
                    });
            }
        } catch (Exception e) {
            outputPanel.displayError("Failed to start analysis: " + e.getMessage());
            finishOperation();
        }
    }

    public void startRenameOperation(boolean renameAll) {
        startOperation();
        try {
            analysisOptionsPanel.saveState();
            Function currentFunction = analysisManager.getCurrentFunction();
            if (currentFunction == null) {
                outputPanel.displayError("No function selected");
                finishOperation();
                return;
            }

            if (!renameAll) {
                // Single function rename
                outputPanel.startRenaming(currentFunction.getName());
                analysisManager.suggestRenames(currentFunction, 0)
                    .thenAccept(result -> {
                        if (result != null) {
                            outputPanel.appendOutput("Suggested function name: " + result.getFunctionName() + "\n\n");
                            if (result.getVariableNames() != null) {
                                outputPanel.appendOutput("Suggested variable names:\n");
                                result.getVariableNames().forEach((oldName, newName) -> 
                                    outputPanel.appendOutput(String.format("  %s → %s\n", oldName, newName))
                                );
                            }
                        }
                        handleAnalysisComplete();
                    })
                    .exceptionally(e -> {
                        handleAnalysisError(e.getMessage());
                        return null;
                    });
            } else {
                // Get all functions and count them
                Program program = currentFunction.getProgram();
                List<Function> allFunctions = new ArrayList<>();
                program.getFunctionManager().getFunctions(true).forEach(allFunctions::add);
                
                // Start batch rename with total count
                outputPanel.startBatchAnalysis(allFunctions.size());
                AtomicInteger completed = new AtomicInteger(0);
                List<java.util.concurrent.CompletableFuture<Void>> futures = new ArrayList<>();
                
                allFunctions.forEach(function -> {
                    futures.add(analysisManager.suggestRenames(function, 0)
                        .thenAccept(result -> {
                            if (result != null) {
                                outputPanel.appendOutput("\nFunction: " + function.getName() + "\n");
                                outputPanel.appendOutput("Suggested name: " + result.getFunctionName() + "\n");
                                if (result.getVariableNames() != null && !result.getVariableNames().isEmpty()) {
                                    outputPanel.appendOutput("Variable suggestions:\n");
                                    result.getVariableNames().forEach((oldName, newName) -> 
                                        outputPanel.appendOutput(String.format("  %s → %s\n", oldName, newName))
                                    );
                                }
                                outputPanel.appendOutput("----------------------------------------\n");
                            }
                            outputPanel.updateBatchProgress(completed.incrementAndGet(), allFunctions.size());
                        })
                        .exceptionally(e -> {
                            handleAnalysisError("Error analyzing " + function.getName() + ": " + e.getMessage());
                            return null;
                        }));
                });
                
                // Wait for all rename operations to complete
                java.util.concurrent.CompletableFuture.allOf(futures.toArray(new java.util.concurrent.CompletableFuture[0]))
                    .thenRun(() -> {
                        outputPanel.appendOutput("\nBatch rename analysis complete.\n");
                        handleAnalysisComplete();
                    })
                    .exceptionally(e -> {
                        handleAnalysisError("Error during batch rename: " + e.getMessage());
                        return null;
                    });
            }
        } catch (Exception e) {
            outputPanel.displayError("Failed to start renaming: " + e.getMessage());
            finishOperation();
        }
    }

    private void startSimulateOperation() {
        startOperation();
        try {
            Function currentFunction = analysisManager.getCurrentFunction();
            if (currentFunction == null) {
                outputPanel.displayError("No function selected");
                finishOperation();
                return;
            }

            outputPanel.startAnalysis("Simulating function: " + currentFunction.getName());
            simulationOperation.executeSimulation(currentFunction, simulationConfigPanel.getConfiguration());
        } catch (Exception e) {
            outputPanel.displayError("Failed to start simulation: " + e.getMessage());
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

    // Getter methods for UI components
    public AnalysisOptionsPanel getAnalysisOptionsPanel() {
        return analysisOptionsPanel;
    }

    public SimulationConfigPanel getSimulationConfigPanel() {
        return simulationConfigPanel;
    }

    public AnalysisOutputPanel getOutputPanel() {
        return outputPanel;
    }

    public OperationButtonPanel getButtonPanel() {
        return buttonPanel;
    }

    public LLMAnalysisManager getAnalysisManager() {
        return analysisManager;
    }
}
