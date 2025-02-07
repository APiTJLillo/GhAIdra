package ghidra.plugins.llm.providers.azure;

import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.LLMProvider;
import ghidra.plugins.llm.RenamingResponse;
import ghidra.plugins.llm.FunctionSummaryResponse;
import ghidra.util.Msg;
import java.util.concurrent.CompletableFuture;

/**
 * Azure DeepSeek model provider implementation.
 */
public class AzureDeepseekProvider implements LLMProvider {
    private AzureDeepseekConfig config;

    @Override
    public void configure(LLMConfig config) {
        if (!(config instanceof AzureDeepseekConfig)) {
            throw new IllegalArgumentException("Expected AzureDeepseekConfig");
        }
        this.config = (AzureDeepseekConfig) config;
    }

    @Override
    public CompletableFuture<RenamingResponse> analyze(String prompt) {
        Msg.debug(this, "Using DeepSeek model for renaming");
        RenamingResponse response = new RenamingResponse();
        response.setError("DeepSeek provider does not support renaming yet");
        return CompletableFuture.completedFuture(response);
    }

    @Override
    public CompletableFuture<FunctionSummaryResponse> analyzeFunction(String prompt) {
        Msg.debug(this, "Using DeepSeek model for analysis");
        FunctionSummaryResponse response = new FunctionSummaryResponse();
        response.setSummary("DeepSeek provider does not support function analysis yet");
        return CompletableFuture.completedFuture(response);
    }

    @Override
    public void dispose() {
        // No resources to clean up
    }
}
