package ghidra.plugins.llm;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.GlobalSymbolMap;
import ghidra.util.task.TaskMonitor;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import java.util.Iterator;
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

    private List<Function> findSimilarFunctions(Function function) {
        List<Function> similarFunctions = new ArrayList<>();
        if (!config.isRenameSimilarFunctions() || function == null) {
            return similarFunctions;
        }

        try {
            // Get signature of source function
            FunctionSignature sourceSig = getFunctionSignature(function);
            if (sourceSig == null) {
                return similarFunctions;
            }

            // Get all functions in program
            Iterator<Function> functions = currentProgram.getFunctionManager().getFunctions(true);
            while (functions.hasNext()) {
                Function targetFunc = functions.next();
                // Skip if it's the same function (compare by entry point to be safe)
                if (targetFunc.equals(function) || 
                    targetFunc.getEntryPoint().equals(function.getEntryPoint())) {
                    continue;
                }

                FunctionSignature targetSig = getFunctionSignature(targetFunc);
                if (targetSig != null && targetSig.equals(sourceSig)) {
                    similarFunctions.add(targetFunc);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error finding similar functions: " + e.getMessage());
        }

        return similarFunctions;
    }

    private FunctionSignature getFunctionSignature(Function function) {
        if (function == null) {
            return null;
        }

        List<InstructionDef> signature = new ArrayList<>();
        Iterator<Instruction> instructions = currentProgram.getListing()
            .getInstructions(function.getBody(), true);

        while (instructions.hasNext()) {
            Instruction inst = instructions.next();
            int[] opTypes = new int[inst.getNumOperands()];
            for (int i = 0; i < inst.getNumOperands(); i++) {
                opTypes[i] = inst.getOperandType(i);
            }
            signature.add(new InstructionDef(inst.getMnemonicString(), opTypes));
        }

        return new FunctionSignature(signature);
    }

    private static class InstructionDef {
        private final String mnemonic;
        private final int[] operandTypes;

        public InstructionDef(String mnemonic, int[] operandTypes) {
            this.mnemonic = mnemonic;
            this.operandTypes = operandTypes;
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof InstructionDef)) {
                return false;
            }
            InstructionDef other = (InstructionDef) obj;
            if (!mnemonic.equals(other.mnemonic)) {
                return false;
            }
            if (operandTypes.length != other.operandTypes.length) {
                return false;
            }
            for (int i = 0; i < operandTypes.length; i++) {
                if (operandTypes[i] != other.operandTypes[i]) {
                    return false;
                }
            }
            return true;
        }

        @Override
        public int hashCode() {
            int hash = mnemonic.hashCode();
            for (int type : operandTypes) {
                hash = 31 * hash + type;
            }
            return hash;
        }
    }

    private static class FunctionSignature {
        private final List<InstructionDef> instructions;

        public FunctionSignature(List<InstructionDef> instructions) {
            this.instructions = instructions;
        }

        @Override
        public boolean equals(Object obj) {
            if (!(obj instanceof FunctionSignature)) {
                return false;
            }
            FunctionSignature other = (FunctionSignature) obj;
            if (instructions.size() != other.instructions.size()) {
                return false;
            }
            for (int i = 0; i < instructions.size(); i++) {
                if (!instructions.get(i).equals(other.instructions.get(i))) {
                    return false;
                }
            }
            return true;
        }

        @Override
        public int hashCode() {
            int hash = 1;
            for (InstructionDef inst : instructions) {
                hash = 31 * hash + inst.hashCode();
            }
            return hash;
        }
    }

    private void applyRenamingSuggestions(Function function, RenamingResponse response) {
        if (response == null || !response.isValid()) {
            return;
        }

        try {
            // Rename the function if a new name is suggested
            if (response.getFunctionName() != null && !response.getFunctionName().isEmpty()) {
                // Wait for any auto-analysis to complete
                AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(currentProgram);
                if (analysisManager != null && analysisManager.isAnalyzing()) {
                    analysisManager.waitForAnalysis(5000, TaskMonitor.DUMMY); // Wait up to 5 seconds
                }

                String oldName = function.getName();
                int transactionId = currentProgram.startTransaction("Rename Function");
                try {
                    function.setName(response.getFunctionName(), SourceType.USER_DEFINED);
                    currentProgram.flushEvents();
                    Thread.sleep(100); // Small delay to let changes settle
                    currentProgram.endTransaction(transactionId, true);
                } catch (Exception e) {
                    currentProgram.endTransaction(transactionId, false);
                    throw e;
                }

                // Verify the rename persisted
                Function verifyFunc = currentProgram.getFunctionManager()
                    .getFunctionAt(function.getEntryPoint());
                if (verifyFunc != null && verifyFunc.getName().equals(response.getFunctionName())) {
                    Msg.info(this, String.format("Renamed function from %s to %s", 
                        oldName, response.getFunctionName()));
                } else {
                    Msg.error(this, String.format("Function rename did not persist: %s", oldName));
                }
            }

            // Rename variables
            Map<String, String> variableNames = response.getVariableNames();
            if (variableNames != null && !variableNames.isEmpty()) {
                DecompileResults decompileResults = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                if (decompileResults.decompileCompleted()) {
                    // Get function reference
                    Function currentFn = currentProgram.getFunctionManager()
                        .getFunctionContaining(function.getEntryPoint());
                    
                    if (currentFn != null) {
                        // Get the decompiled function representation
                        ghidra.app.decompiler.DecompiledFunction decompFn = decompileResults.getDecompiledFunction();
                        String decompSrc = decompFn.getC();
                        
                        // Log the current state
                        Msg.debug(this, "Decompiled source:\n" + decompSrc);
                        Msg.debug(this, "\nRename suggestions:");
                        variableNames.forEach((k, v) -> Msg.debug(this, String.format("  %s → %s", k, v)));
                        
                        // Create variable trackers for different types
                        Set<String> processedVars = new HashSet<>();
                        
                        // 1. Process parameters
                        Variable[] parameters = currentFn.getParameters();
                        for (Variable param : parameters) {
                            String oldName = param.getName();
                            // Handle parameters specially to ensure they stick
            if (variableNames.containsKey(oldName)) {
                String newName = variableNames.get(oldName);
                int transactionId = currentProgram.startTransaction("Rename Parameter");
                try {
                    // Ensure no ongoing analysis before parameter rename
                    AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(currentProgram);
                    if (analysisManager != null && analysisManager.isAnalyzing()) {
                        analysisManager.waitForAnalysis(5000, TaskMonitor.DUMMY);
                    }

                    // Update parameter in function signature first
                    Function func = param.getFunction();
                    Variable[] params = func.getParameters();
                    int index = -1;
                    for (int i = 0; i < params.length; i++) {
                        if (params[i].equals(param)) {
                            index = i;
                            break;
                        }
                    }
                    if (index >= 0) {
                        // Update the parameter directly in the function
                        param.setName(newName, SourceType.USER_DEFINED);
                        // Force signature update
                        func.updateFunction(
                            null,  // keep current name
                            null,  // keep current return type
                            Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
                            true,  // force update
                            SourceType.USER_DEFINED
                        );
                    } else {
                        // Fallback to direct rename if not found in signature
                        param.setName(newName, SourceType.USER_DEFINED);
                    }
                    currentProgram.flushEvents();
                    Thread.sleep(250); // Longer delay for parameters
                    // Update high-level parameter info
                    LocalSymbolMap symbolMap = decompileResults.getHighFunction().getLocalSymbolMap();
                    Iterator<HighSymbol> symbols = symbolMap.getSymbols();
                    HighSymbol paramSymbol = null;
                    while (symbols.hasNext()) {
                        HighSymbol sym = symbols.next();
                        if (sym.isParameter() && sym.getName().equals(oldName)) {
                            paramSymbol = sym;
                            break;
                        }
                    }
                    if (paramSymbol != null) {
                        HighFunctionDBUtil.updateDBVariable(paramSymbol, newName, null, SourceType.USER_DEFINED);
                    }
                    currentProgram.endTransaction(transactionId, true);
                    processedVars.add(oldName);
                    Msg.info(this, String.format("Renamed parameter %s to %s (storage: %s)", 
                        oldName, newName, param.getVariableStorage()));
                } catch (Exception e) {
                    currentProgram.endTransaction(transactionId, false);
                    Msg.error(this, String.format("Failed to rename parameter %s: %s", oldName, e.getMessage()));
                }
            }
                        }
                        
                        // 2. Process all local variables
                        Variable[] locals = currentFn.getAllVariables();
                        for (Variable local : locals) {
                            // Skip parameters as we already processed them
                            if (!processedVars.contains(local.getName())) {
                                String oldName = local.getName();
                                processVariable(local, oldName, variableNames, processedVars);
                            }
                        }
                        
                        // 3. Process stack variables specifically to ensure we don't miss any
                        LocalSymbolMap localMap = decompileResults.getHighFunction().getLocalSymbolMap();
                        Iterator<HighSymbol> symbolIterator = localMap.getSymbols();
                        while (symbolIterator.hasNext()) {
                            HighSymbol symbol = symbolIterator.next();
                            String oldName = symbol.getName();
                            if (variableNames.containsKey(oldName) && !processedVars.contains(oldName)) {
                                String newName = variableNames.get(oldName);
                                int transactionId = currentProgram.startTransaction("Rename Variable");
                                try {
                                    HighFunctionDBUtil.updateDBVariable(symbol, newName, null, SourceType.ANALYSIS);
                                    currentProgram.endTransaction(transactionId, true);
                                    processedVars.add(oldName);
                                    Msg.info(this, String.format("Renamed %s to %s", oldName, newName));
                                } catch (Exception e) {
                                    currentProgram.endTransaction(transactionId, false);
                                    Msg.error(this, String.format("Failed to rename %s: %s", oldName, e.getMessage()));
                                }
                            }
                        }

                        // 3. Process global variables if they match our patterns
                        variableNames.keySet().stream()
                            .filter(name -> name.startsWith("DAT_") || name.startsWith("PTR_"))
                            .forEach(name -> {
                                try {
                                    ghidra.program.model.symbol.SymbolIterator symbols = 
                                        currentProgram.getSymbolTable().getSymbols(name);
                                    while (symbols.hasNext()) {
                                        ghidra.program.model.symbol.Symbol symbol = symbols.next();
                                        if (symbol != null) {
                                            String newName = variableNames.get(name);
                                            symbol.setName(newName, SourceType.USER_DEFINED);
                                            processedVars.add(name);
                                            Msg.info(this, String.format("Renamed global %s to %s", 
                                                name, newName));
                                        }
                                    }
                                } catch (Exception e) {
                                    Msg.debug(this, String.format(
                                        "Could not process global variable %s: %s", 
                                        name, e.getMessage()));
                                }
                            });
                        
                        // 4. Try to handle any remaining field variables or references
                        variableNames.keySet().stream()
                            .filter(name -> !processedVars.contains(name))
                            .forEach(name -> {
                                try {
                                    // Look for symbols with this name in function's scope
                                    ghidra.program.model.symbol.SymbolIterator symbols = 
                                        currentProgram.getSymbolTable().getSymbols(name);
                                    if (symbols.hasNext()) {
                                        ghidra.program.model.symbol.Symbol symbol = symbols.next();
                                        String newName = variableNames.get(name);
                                        symbol.setName(newName, SourceType.USER_DEFINED);
                                        processedVars.add(name);
                                        Msg.info(this, String.format("Renamed symbol %s to %s", 
                                            name, newName));
                                    }
                                } catch (Exception e) {
                                    Msg.debug(this, String.format(
                                        "Could not process symbol %s: %s", 
                                        name, e.getMessage()));
                                }
                            });
                        
                        // Log any variables we still couldn't find
                        variableNames.keySet().stream()
                            .filter(name -> !processedVars.contains(name))
                            .forEach(name -> Msg.debug(this, 
                                String.format("Could not find variable in program: %s", name)));
                    }
                    
                    // Clean refresh of decompiler view
                    decompiler.dispose();
                    initializeDecompiler();
                    decompileResults = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
                } else {
                    Msg.error(this, "Failed to decompile function for variable renaming: " + function.getName());
                }
            }
        } catch (Exception e) {
            Msg.error(this, "Error applying renaming suggestions: " + e.getMessage());
        }
    }

    private void processVariable(Variable var, String oldName, Map<String, String> variableNames,
            Set<String> processedVars) {
        String newName = variableNames.get(oldName);
        if (newName != null && !newName.isEmpty()) {
            try {
                // For all variables, just apply the new name - the high level interface
                // already handles the proper storage type
                // Wait for any auto-analysis to complete
                AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(currentProgram);
                if (analysisManager != null && analysisManager.isAnalyzing()) {
                    analysisManager.waitForAnalysis(5000, TaskMonitor.DUMMY); // Wait up to 5 seconds
                }

                int transactionId = currentProgram.startTransaction("Rename Variable");
                try {
                    var.setName(newName, SourceType.USER_DEFINED);
                    currentProgram.flushEvents();
                    Thread.sleep(100); // Small delay to let changes settle
                    currentProgram.endTransaction(transactionId, true);
                } catch (Exception e) {
                    currentProgram.endTransaction(transactionId, false);
                    throw e;
                }

                // Verify the rename persisted
                Variable[] allVars = var.getFunction().getAllVariables();
                boolean verified = false;
                for (Variable v : allVars) {
                    if (v.getName().equals(newName)) {
                        verified = true;
                        break;
                    }
                }
                if (verified) {
                    Msg.info(this, String.format("Renamed %s to %s (storage: %s)", 
                        oldName, newName, var.getVariableStorage()));
                } else {
                    Msg.error(this, String.format("Variable rename did not persist: %s", oldName));
                }
                processedVars.add(oldName);
            } catch (Exception e) {
                Msg.error(this, String.format("Failed to rename %s: %s", oldName, e.getMessage()));
            }
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
                """
                Analyze the provided decompiled function and suggest semantically meaningful names for the function and all variables.

                Current function name: %s
                Signature: %s

                Decompiled Code:
                %s

                Important Instructions:
                1. Do not change or strip any variable prefixes
                2. Use the EXACT variable names as they appear in the code as keys
                3. Include suggestions for ALL variables, including:
                   - Stack variables (uStack_XX, ppuStack_XX)
                   - Register variables (iVarX, puVar1, pcVar1, etc.)
                   - Local variables (local_XX)
                   - Parameters (param_X)
                   - Global variables (DAT_XXX, PTR_XXX)
                   - Field variables or references

                Naming Guidelines:
                - Names should be descriptive and indicate purpose/role
                - Consider data types when suggesting names (pointer, array, string, etc.)
                - Use consistent naming conventions
                - Preserve type information in names (e.g., 'ptr' for pointers)
                - Base names on how variables are used in the code
                - Consider function context and parameters when naming variables

                Example JSON format:
                {
                    "functionName": "suggestedName",
                    "variableNames": {
                        "uStack_24": "configBuffer",
                        "ppuStack_28": "dataPointer",
                        "iVar1": "loopCounter",
                        "local_10": "tempResult",
                        "param_1": "inputSize",
                        "DAT_0040a000": "globalConfig"
                    }
                }

                NOTE: Variable names must match EXACTLY as they appear in the code.
                """,
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

                        // Find and rename similar functions if enabled
                        if (config.isRenameSimilarFunctions() && response.getFunctionName() != null && !response.getFunctionName().isEmpty()) {
                            List<Function> similarFunctions = findSimilarFunctions(function);
                            if (!similarFunctions.isEmpty()) {
                                Msg.info(this, String.format("Found %d similar functions to rename", similarFunctions.size()));
                                for (Function similar : similarFunctions) {
                                    String oldName = similar.getName();
                                    similar.setName(response.getFunctionName(), SourceType.USER_DEFINED);
                                    Msg.info(this, String.format("Renamed similar function from %s to %s", 
                                        oldName, response.getFunctionName()));
                                }
                            }
                        }

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
            if (renamingResponse != null && currentProgram != null && !currentProgram.isClosed()) {
                Set<Function> childFunctions;
                try {
                    childFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
                } catch (Exception e) {
                    Msg.error(this, "Error getting called functions: " + e.getMessage());
                    return CompletableFuture.completedFuture(renamingResponse);
                }
                
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
            if (currentProgram == null || currentProgram.isClosed()) {
                return CompletableFuture.completedFuture(result);
            }

            Set<Function> childFunctions;
            try {
                childFunctions = function.getCalledFunctions(TaskMonitor.DUMMY);
            } catch (Exception e) {
                Msg.error(this, "Error getting called functions: " + e.getMessage());
                return CompletableFuture.completedFuture(result);
            }

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

            return childAnalyses.exceptionally(e -> {
                Msg.error(this, "Error during recursive analysis: " + e.getMessage());
                return result;
            });
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
