package ghidra.plugins.llm.providers.ollama;

import ghidra.plugins.llm.LLMProvider;
import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.RenamingResponse;
import ghidra.plugins.llm.FunctionSummaryResponse;

import java.util.concurrent.CompletableFuture;

public class OllamaProvider implements LLMProvider {

    @Override
    public void configure(LLMConfig config) {
        if (!(config instanceof OllamaConfig)) {
            throw new IllegalArgumentException("Invalid config type for OllamaProvider");
        }
        // Configuration logic for Ollama provider
    }

    private void setupClient() {
        // Setup client logic for Ollama provider
    }

    @Override
    public CompletableFuture<RenamingResponse> analyze(String prompt) {
        // Analyze logic for Ollama provider
        return CompletableFuture.completedFuture(new RenamingResponse());
    }

    @Override
    public CompletableFuture<FunctionSummaryResponse> analyzeFunction(String prompt) {
        // Analyze function logic for Ollama provider
        return CompletableFuture.completedFuture(new FunctionSummaryResponse());
    }

    @Override
    public void dispose() {
        // Dispose resources for Ollama provider
    }
}
