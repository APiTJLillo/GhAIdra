package ghidra.plugins.llm;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import java.util.*;

/**
 * Analyzes functions and suggests appropriate input values for simulation.
 */
public class AIInputSuggester {
    private final LLMProvider llmProvider;
    private final DecompInterface decompiler;

    public AIInputSuggester(LLMProvider llmProvider, DecompInterface decompiler) {
        this.llmProvider = llmProvider;
        this.decompiler = decompiler;
    }

    /**
     * Analyzes a function and suggests input values for its parameters.
     * @param function The function to analyze
     * @return Map of parameter names to suggested values
     */
    public Map<String, Long> suggestInputs(Function function) {
        Map<String, Long> suggestions = new HashMap<>();
        
        try {
            // Get decompiled code for better analysis
            DecompileResults results = decompiler.decompileFunction(function, 0, null);
            String decompiledCode = results.getDecompiledFunction().getC();
            
            // Build context for LLM
            StringBuilder context = new StringBuilder();
            context.append("Function Name: ").append(function.getName()).append("\n\n");
            context.append("Decompiled Code:\n").append(decompiledCode).append("\n\n");
            context.append("Parameters:\n");
            
            for (Parameter param : function.getParameters()) {
                context.append("- ").append(param.getDataType().getName())
                       .append(" ").append(param.getName())
                       .append("\n");
            }
            
            // Request suggestions from LLM
            String prompt = "Based on the following function code and parameters, suggest realistic test input values. " +
                          "Consider the function's purpose, parameter types, and any constraints visible in the code. " +
                          "For each parameter, explain why the suggested value would be meaningful for testing.\n\n" +
                          context.toString();

            String aiResponse = llmProvider.processPrompt(prompt);
            
            // Parse AI suggestions and generate values
            suggestions.putAll(parseAISuggestions(aiResponse, function));
            
            // If AI didn't provide suggestions for some parameters, use heuristic defaults
            for (Parameter param : function.getParameters()) {
                if (!suggestions.containsKey(param.getName())) {
                    suggestions.put(param.getName(), generateDefaultValue(param.getDataType()));
                }
            }
            
        } catch (Exception e) {
            // Fallback to heuristic-based suggestions if AI analysis fails
            for (Parameter param : function.getParameters()) {
                suggestions.put(param.getName(), generateDefaultValue(param.getDataType()));
            }
        }
        
        return suggestions;
    }

    /**
     * Parse AI-generated suggestions into parameter values.
     */
    private Map<String, Long> parseAISuggestions(String aiResponse, Function function) {
        Map<String, Long> values = new HashMap<>();
        
        // Extract numeric values from AI response
        for (Parameter param : function.getParameters()) {
            String pattern = param.getName() + "\\s*[=:]\\s*(-?\\d+)";
            java.util.regex.Pattern regex = java.util.regex.Pattern.compile(pattern);
            java.util.regex.Matcher matcher = regex.matcher(aiResponse);
            
            if (matcher.find()) {
                try {
                    long value = Long.parseLong(matcher.group(1));
                    values.put(param.getName(), value);
                } catch (NumberFormatException e) {
                    // Skip if value can't be parsed
                }
            }
        }
        
        return values;
    }

    /**
     * Generate default test values based on parameter type.
     */
    private long generateDefaultValue(DataType dataType) {
        if (dataType instanceof IntegerDataType) {
            // Use common test values for integers
            return 42; // A recognizable test value
        } else if (dataType instanceof PointerDataType) {
            // For pointers, allocate some memory space
            return 0x1000; // A reasonable starting address for test memory
        } else {
            // For other types, use a small non-zero value
            return 1;
        }
    }

    /**
     * Analyzes simulation results to suggest improved inputs.
     */
    public Map<String, Long> refineInputs(Function function, PCODESimulator.SimulationResult previousResult,
                                      Map<String, Long> previousInputs) {
        Map<String, Long> refinedInputs = new HashMap<>(previousInputs);
        
        try {
            StringBuilder feedbackContext = new StringBuilder();
            feedbackContext.append("Previous simulation results:\n");
            
            // Add execution trace info
            if (!previousResult.getExecutionTrace().isEmpty()) {
                feedbackContext.append("Execution path covered: ")
                             .append(previousResult.getExecutionTrace().size())
                             .append(" instructions\n");
            }
            
            // Add error information if any
            if (previousResult.hasErrors()) {
                feedbackContext.append("Errors encountered:\n");
                for (String error : previousResult.getErrors()) {
                    feedbackContext.append("- ").append(error).append("\n");
                }
            }
            
            // Add return value if present
            if (previousResult.getReturnValue() != null) {
                feedbackContext.append("Return value: ")
                             .append(previousResult.getReturnValue())
                             .append("\n");
            }
            
            String prompt = "Based on the previous simulation results, suggest improved input values " +
                          "to achieve better code coverage or handle errors:\n\n" + 
                          feedbackContext.toString();
            
            String aiResponse = llmProvider.processPrompt(prompt);
            Map<String, Long> suggestions = parseAISuggestions(aiResponse, function);
            
            // Only update values that the AI specifically suggested changes for
            refinedInputs.putAll(suggestions);
            
        } catch (Exception e) {
            // Keep previous inputs if refinement fails
        }
        
        return refinedInputs;
    }
}
