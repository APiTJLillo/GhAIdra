package ghidra.plugins.llm;

import java.util.concurrent.CompletableFuture;

/**
 * Interface for LLM providers. Each provider (Azure, Ollama, etc.) must implement this interface.
 */
public interface LLMProvider {
    /**
     * Configures the provider with its specific configuration.
     * @param config The provider-specific configuration
     */
    void configure(LLMConfig config);

    /**
     * Analyzes text with general context.
     * @param prompt The text to analyze
     * @return A future containing the analysis result
     */
    CompletableFuture<String> analyze(String prompt);

    /**
     * Analyzes a function with specific reverse engineering context.
     * @param prompt The function text to analyze
     * @return A future containing the analysis result
     */
    CompletableFuture<String> analyzeFunction(String prompt);

    /**
     * Releases any resources held by the provider.
     */
    void dispose();
}
