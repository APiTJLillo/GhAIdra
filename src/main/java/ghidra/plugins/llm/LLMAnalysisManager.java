package ghidra.plugins.llm;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;

import java.util.concurrent.CompletableFuture;
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import ghidra.plugins.llm.config.ConfigManager;

/**
 * Manages LLM-based analysis operations including recursive analysis and renaming.
 */
public class LLMAnalysisManager {
    private final LLMProviderRegistry registry;
    private final ConfigManager configManager;
    private AnalysisConfig config;
    private Set<String> processedFunctions;
    private Program currentProgram;
    private DecompInterface decompiler;

    public LLMAnalysisManager(Program program) {
        this.registry = LLMProviderRegistry.getInstance();
        this.configManager = ConfigManager.getInstance();
        this.config = new AnalysisConfig();
        this.processedFunctions = new HashSet<>();
        this.currentProgram = program;
        initializeDecompiler();
    }

    private void initializeDecompiler() {
        decompiler = new DecompInterface();
        if (currentProgram != null) {
            decompiler.openProgram(currentProgram);
        }
    }

    public void setProgram(Program program) {
        this.currentProgram = program;
        if (decompiler != null) {
            decompiler.dispose();
        }
        initializeDecompiler();
    }

    public void setConfig(AnalysisConfig config) {
        this.config = config;
    }

    public AnalysisConfig getConfig() {
        return config;
    }

    private String decompileFunction(Function function) {
        if (function == null) return "";
        
        DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
        if (results.decompileCompleted()) {
            return results.getDecompiledFunction().getC();
        }
        return "";
    }

    private String buildAnalysisPrompt(Function function, String decompiled) {
        return String.format("""
            Analyze the following function:

            Function Name: %s
            Entry Point: %s
            Signature: %s

            Decompiled Code:
            %s

            Provide analysis in the specified JSON format focusing on:
            1. A concise one-line summary of the function's purpose
            2. Detailed explanation of functionality
            3. Key algorithms or patterns identified
            4. Security implications or concerns
            """, 
            function.getName(),
            function.getEntryPoint(),
            function.getSignature(),
            decompiled);
    }

    private void applyRenamingSuggestions(Function function, RenamingResponse response) {
        if (response == null || !response.isValid()) {
            return;
        }

        try {
            // Rename the function if a new name is suggested
            if (response.getFunctionName() != null && !response.getFunctionName().isEmpty()) {
                function.setName(response.getFunctionName(), SourceType.USER_DEFINED);
                Msg.info(this, String.format("Renamed function from %s to %s", 
                    function.getName(), response.getFunctionName()));
            }

            // Rename variables
            Map<String, String> variableNames = response.getVariableNames();
            if (variableNames != null && !variableNames.isEmpty()) {
                DecompileResults decompileResults = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                if (decompileResults.decompileCompleted()) {
                    // Get all variables from the function
                    Variable[] allVars = function.getAllVariables();
                    
                    for (Variable var : allVars) {
                        String oldName = var.getName();
                        String newName = variableNames.get(oldName);
                        if (newName != null && !newName.isEmpty()) {
                            try {
                                var.setName(newName, SourceType.USER_DEFINED);
                                Msg.info(this, String.format("Renamed variable from %s to %s in function %s", 
                                    oldName, newName, function.getName()));
                            } catch (Exception e) {
                                Msg.error(this, String.format("Failed to rename variable %s to %s: %s", 
                                    oldName, newName, e.getMessage()));
                            }
                        }
                    }
                } else {
                    Msg.error(this, "Failed to decompile function for variable renaming: " + function.getName());
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error applying renaming suggestions: " + e.getMessage());
        }
    }

    public CompletableFuture<RenamingResponse> suggestRenames(Function function, int depth) {
        if (function == null || processedFunctions.contains(function.getName())) {
            return CompletableFuture.completedFuture(null);
        }

        String functionBody = decompileFunction(function);
        if (functionBody.isEmpty()) {
            RenamingResponse error = new RenamingResponse();
            error.setError("Failed to decompile function");
            return CompletableFuture.completedFuture(error);
        }

        processedFunctions.add(function.getName());

        String internalName = configManager.getDefaultRenamingProvider();
        if (internalName == null || internalName.isEmpty()) {
            internalName = "azure-openai"; // Default to Azure OpenAI if none specified
        }

        LLMProvider provider;
        try {
            provider = registry.getProvider(internalName);
        } catch (Exception e) {
            RenamingResponse error = new RenamingResponse();
            error.setError("Error getting provider '" + internalName + "': " + e.getMessage());
            return CompletableFuture.completedFuture(error);
        }

        // First get the function summary
        CompletableFuture<FunctionSummaryResponse> summary = analyzeFunction(function, depth);
        
        // Then get and apply the renaming suggestions
        CompletableFuture<RenamingResponse> suggestions = provider.analyze(
            String.format(
                "Suggest better names for this function and its variables:\n\n" +
                "Current function name: %s\n" +
                "Signature: %s\n\n%s",
                function.getName(),
                function.getSignature(),
                functionBody
            )
        );

        // Automatically apply the suggestions when they arrive
        suggestions = suggestions.thenCombine(summary, (response, summaryResponse) -> {
            if (response != null && response.isValid()) {
                try {
                    // Apply the renaming suggestions within a transaction
                    int transactionID = currentProgram.startTransaction("Rename Function and Variables");
                    try {
                        applyRenamingSuggestions(function, response);
                        currentProgram.endTransaction(transactionID, true);
                        Msg.info(this, "Successfully applied renaming suggestions for " + function.getName());
                    } catch (Exception e) {
                        currentProgram.endTransaction(transactionID, false);
                        Msg.error(this, "Failed to apply renaming suggestions: " + e.getMessage());
                    }
                } catch (Exception e) {
                    Msg.error(this, "Error starting transaction: " + e.getMessage());
                }
            }
            return response;
        });

        if (!config.isRecursiveRenaming()) {
            return suggestions;
        }

        return suggestions.thenCompose(renamingResponse -> {
            if (renamingResponse != null) {
                Set<Function> childFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
                CompletableFuture<RenamingResponse> childSuggestions = CompletableFuture.completedFuture(renamingResponse);

                for (Function childFunction : childFunctions) {
                    if (!processedFunctions.contains(childFunction.getName())) {
                        childSuggestions = childSuggestions.thenCompose(previous ->
                            suggestRenames(childFunction, depth + 1)
                            .thenApply(childResult -> {
                                if (childResult != null) {
                                    previous.getVariableNames().putAll(childResult.getVariableNames());
                                }
                                return previous;
                            })
                        );
                    }
                }

                return childSuggestions;
            }
            RenamingResponse error = new RenamingResponse();
            error.setError("Failed to generate renaming suggestions");
            return CompletableFuture.completedFuture(error);
        });
    }

    public CompletableFuture<FunctionSummaryResponse> analyzeFunction(Function function, int depth) {
        if (function == null || processedFunctions.contains(function.getName())) {
            return CompletableFuture.completedFuture(null);
        }

        String functionBody = decompileFunction(function);
        if (functionBody.isEmpty()) {
            FunctionSummaryResponse error = new FunctionSummaryResponse();
            error.setSummary("Failed to decompile function");
            return CompletableFuture.completedFuture(error);
        }

        processedFunctions.add(function.getName());
        
        String internalName = configManager.getDefaultAnalysisProvider();
        if (internalName == null || internalName.isEmpty()) {
            internalName = "azure-openai"; // Default to Azure OpenAI if none specified
        }

        LLMProvider provider;
        try {
            provider = registry.getProvider(internalName);
        } catch (Exception e) {
            FunctionSummaryResponse error = new FunctionSummaryResponse();
            error.setSummary("Error getting provider '" + internalName + "': " + e.getMessage());
            return CompletableFuture.completedFuture(error);
        }

        String prompt = buildAnalysisPrompt(function, functionBody);
        CompletableFuture<FunctionSummaryResponse> analysis = provider.analyzeFunction(prompt)
            .thenApply(summary -> {
                // Log the function summary
                Msg.info(this, String.format("[Function Summary] %s: %s", 
                    function.getName(), summary.getSummary()));
                return summary;
            })
            .exceptionally(e -> {
                String error = "Error during analysis: " + 
                    (e.getCause() != null ? e.getCause().getMessage() : e.getMessage());
                Msg.error(this, error);
                return null;
            });

        if (!config.isRecursiveAnalysis()) {
            return analysis;
        }

        return analysis.thenCompose(result -> {
            Set<Function> childFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
            CompletableFuture<FunctionSummaryResponse> childAnalyses = CompletableFuture.completedFuture(result);

            for (Function childFunction : childFunctions) {
                if (!processedFunctions.contains(childFunction.getName())) {
                    childAnalyses = childAnalyses.thenCompose(previous -> 
                        analyzeFunction(childFunction, depth + 1)
                        .thenApply(childResult -> {
                            if (childResult != null) {
                                String currentSummary = previous.getSummary();
                                previous.setSummary(currentSummary + 
                                    (currentSummary.isEmpty() ? "" : "\n") + 
                                    "Child function " + childFunction.getName() + ": " + 
                                    childResult.getSummary());
                            }
                            return previous;
                        })
                    );
                }
            }

            return childAnalyses;
        });
    }

    public void resetSession() {
        processedFunctions.clear();
    }

    public void dispose() {
        if (decompiler != null) {
            decompiler.dispose();
            decompiler = null;
        }
    }
}
