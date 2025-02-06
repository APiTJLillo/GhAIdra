package ghidra.plugins.llm;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.concurrent.CompletableFuture;
import java.util.Set;
import java.util.HashSet;
import java.util.ArrayList;
import java.util.List;
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

    /**
     * Updates the analysis configuration.
     * @param config the new configuration
     */
    public void setConfig(AnalysisConfig config) {
        this.config = config;
    }

    public AnalysisConfig getConfig() {
        return config;
    }


    /**
     * Analyzes a function recursively if enabled.
     * @param function the function to analyze
     * @param depth the current recursion depth
     * @return future containing the analysis result
     */
    public CompletableFuture<String> analyzeFunction(Function function, int depth) {
        if (function == null || processedFunctions.contains(function.getName())) {
            return CompletableFuture.completedFuture("");
        }

        String functionBody = decompileFunction(function);
        if (functionBody.isEmpty()) {
            return CompletableFuture.completedFuture("Failed to decompile function");
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
            return CompletableFuture.completedFuture("Error getting provider '" + internalName + "': " + e.getMessage());
        }

        String prompt = buildAnalysisPrompt(function, functionBody);
        CompletableFuture<String> analysis = provider.analyzeFunction(prompt)
            .exceptionally(e -> {
                return "Error during analysis: " + (e.getCause() != null ? e.getCause().getMessage() : e.getMessage());
            });

        if (!config.isRecursiveAnalysis()) {
            return analysis;
        }

        return analysis.thenCompose(result -> {
            // Extract child function calls and analyze them recursively
            Set<Function> childFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
            CompletableFuture<String> childAnalyses = CompletableFuture.completedFuture("");

            for (Function childFunction : childFunctions) {
                if (!processedFunctions.contains(childFunction.getName())) {
                    childAnalyses = childAnalyses.thenCompose(previous -> 
                        analyzeFunction(childFunction, depth + 1)
                        .thenApply(childResult -> previous + "\n" + childResult)
                    );
                }
            }

            return childAnalyses.thenApply(childResults -> 
                result + (childResults.isEmpty() ? "" : "\n\nChild Function Analysis:\n" + childResults)
            );
        });
    }

    /**
     * Renames a function and its variables recursively if enabled.
     * @param function the function to rename
     * @param depth the current recursion depth
     * @return future containing the renaming suggestions
     */
    public CompletableFuture<String> suggestRenames(Function function, int depth) {
        if (function == null || processedFunctions.contains(function.getName())) {
            return CompletableFuture.completedFuture("");
        }

        String functionBody = decompileFunction(function);
        if (functionBody.isEmpty()) {
            return CompletableFuture.completedFuture("Failed to decompile function");
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
            return CompletableFuture.completedFuture("Error getting provider '" + internalName + "': " + e.getMessage());
        }

        CompletableFuture<String> suggestions = provider.analyze(
            String.format(
                "Suggest better names for this function and its variables:\n\n" +
                "Current function name: %s\n" +
                "Signature: %s\n\n%s",
                function.getName(),
                function.getSignature(),
                functionBody
            )
        );

        if (!config.isRecursiveRenaming()) {
            return suggestions;
        }

        return suggestions.thenCompose(result -> {
            // Extract child function calls and analyze them recursively
            Set<Function> childFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
            CompletableFuture<String> childSuggestions = CompletableFuture.completedFuture("");

            for (Function childFunction : childFunctions) {
                if (!processedFunctions.contains(childFunction.getName())) {
                    childSuggestions = childSuggestions.thenCompose(previous ->
                        suggestRenames(childFunction, depth + 1)
                        .thenApply(childResult -> previous + "\n" + childResult)
                    );
                }
            }

            return childSuggestions.thenApply(childResults ->
                result + (childResults.isEmpty() ? "" : "\n\nChild Function Suggestions:\n" + childResults)
            );
        });
    }

    private String buildAnalysisPrompt(Function function, String decompiled) {
        return String.format("""
            Analyze the following function:

            Function Name: %s
            Entry Point: %s
            Signature: %s

            Decompiled Code:
            %s

            Please provide:
            1. Purpose and functionality
            2. Key algorithms or patterns
            3. Security implications
            4. Areas for further analysis
            """, 
            function.getName(),
            function.getEntryPoint(),
            function.getSignature(),
            decompiled);
    }

    private String decompileFunction(Function function) {
        if (function == null) return "";
        
        DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
        if (results.decompileCompleted()) {
            return results.getDecompiledFunction().getC();
        }
        return "";
    }

    /**
     * Resets the processed functions set for a new analysis session.
     */
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
