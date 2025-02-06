/* ###
 * IP: Apache License 2.0
 */
package ghidra.plugins.azure;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompiledFunction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidra.app.services.ConsoleService;

/**
 * Handles function decompilation and analysis
 */
public class FunctionAnalyzer {
    private final Program currentProgram;
    private final ConsoleService console;
    private final DecompInterface decompiler;
    private final AzureAIClient aiClient;

    public FunctionAnalyzer(Program program, ConsoleService console, AzureAIClient aiClient) {
        this.currentProgram = program;
        this.console = console;
        this.aiClient = aiClient;
        this.decompiler = new DecompInterface();
        setupDecompiler();
    }

    private void setupDecompiler() {
        decompiler.openProgram(currentProgram);
    }

    public String analyzeSingleFunction(Function function, TaskMonitor monitor) throws Exception {
        if (monitor.isCancelled()) {
            return null;
        }

        console.println("\nAnalyzing function: " + function.getName());
        monitor.setMessage("Analyzing function: " + function.getName());

        try {
            // Get function details with progress monitoring
            monitor.setMessage("Getting function details...");
            String functionDetails = getFunctionDetails(function);
            
            // Check for cancellation
            if (monitor.isCancelled()) {
                return null;
            }

            // Analyze with AI
            monitor.setMessage("Sending to Azure OpenAI for analysis...");
            String prompt = buildAnalysisPrompt(functionDetails);
            String analysis = aiClient.analyze(prompt);

            console.println("Successfully analyzed " + function.getName());
            return "=== Function Analysis ===\n\n" + analysis;
        }
        catch (Exception e) {
            console.println("Error analyzing " + function.getName() + ": " + e.getMessage());
            throw e;
        }
    }

    private String getFunctionDetails(Function function) {
        StringBuilder details = new StringBuilder();
        try {
            // Basic function information
            details.append("=== Function Information ===\n");
            details.append("Function Name: ").append(function.getName()).append("\n");
            details.append("Entry Point: ").append(function.getEntryPoint()).append("\n");
            details.append("Signature: ").append(function.getSignature()).append("\n");
            details.append("Return Type: ").append(function.getReturnType()).append("\n");
            
            // Get existing comments if any
            String existingComment = function.getComment();
            if (existingComment != null && !existingComment.trim().isEmpty()) {
                details.append("\n=== Existing Comments ===\n");
                details.append(existingComment).append("\n");
            }
            
            // Add information about references to this function
            details.append("\n=== References To This Function ===\n");
            currentProgram.getReferenceManager()
                .getReferencesTo(function.getEntryPoint())
                .forEach(ref -> {
                    if (ref.getReferenceType().isCall()) {
                        details.append("Called from: ").append(ref.getFromAddress()).append("\n");
                    }
                });
            
            // Decompiled code
            details.append("\n=== Decompiled Code ===\n");
            DecompiledFunction decompiled = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY).getDecompiledFunction();
            if (decompiled != null) {
                details.append(decompiled.getC());
            }
            
            return details.toString();
        } catch (Exception e) {
            console.println("Error getting details for " + function.getName() + ": " + e.getMessage());
            return "Error getting function details: " + e.getMessage();
        }
    }

    private String buildAnalysisPrompt(String code) {
        return "You are an expert reverse engineer analyzing decompiled code.\n" +
            "Consider the following aspects:\n" +
            "1. Function purpose and behavior\n" +
            "2. Key algorithms or data structures used\n" +
            "3. Notable code patterns or common functions called\n" +
            "4. Potential security implications\n" +
            "5. Suggestions for variable/function renaming if unclear\n\n" +
            "Code to analyze:\n\n" + code + 
            "\n\nProvide your analysis in a clear, structured format with sections for each aspect.";
    }

    public void dispose() {
        if (decompiler != null) {
            decompiler.dispose();
        }
    }
}
