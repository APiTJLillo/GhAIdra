package ghidra.plugins.llm;

import java.util.concurrent.CompletableFuture;

/**
 * Interface for LLM providers that can analyze code and suggest improvements.
 */
public interface LLMProvider {
    /**
     * Configures the provider with the given configuration.
     * @param config the configuration to use
     */
    void configure(LLMConfig config);

    /**
     * Analyzes the given code and suggests renames.
     * @param prompt the code analysis prompt 
     * @return future containing renaming suggestions
     */
    CompletableFuture<RenamingResponse> analyze(String prompt);

    /**
     * Analyzes a function for detailed understanding.
     * @param prompt the function analysis prompt
     * @return future containing the function analysis
     */
    CompletableFuture<FunctionSummaryResponse> analyzeFunction(String prompt);

    /**
     * Disposes of any resources used by this provider.
     */
    void dispose();
}
