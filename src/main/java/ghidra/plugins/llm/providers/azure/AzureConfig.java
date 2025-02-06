package ghidra.plugins.llm.providers.azure;

import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.config.ConfigManager;

/**
 * Configuration class for Azure OpenAI provider.
 */
public class AzureConfig implements LLMConfig {
    private final ConfigManager config;
    private String endpoint;
    private String key;
    private String model;
    private String displayName;

    public AzureConfig() {
        this.config = ConfigManager.getInstance();
        // Load values from config
        this.endpoint = config.getAzureEndpoint();
        this.key = config.getAzureKey();
        this.model = config.getModelForAnalysis();
        this.displayName = "Azure OpenAI";
    }

    public AzureConfig(String endpoint, String key, String model, String displayName) {
        this.config = ConfigManager.getInstance();
        // Initialize with provided values
        this.endpoint = endpoint;
        this.key = key;
        this.model = model;
        this.displayName = displayName != null ? displayName : "Azure OpenAI";
    }

    @Override
    public boolean isValid() {
        return endpoint != null && !endpoint.isEmpty() && 
               key != null && !key.isEmpty();
    }

    @Override
    public String getProviderType() {
        return "azure-openai";
    }

    @Override
    public void setDisplayName(String name) {
        this.displayName = name;
    }

    @Override
    public String getDisplayName() {
        return displayName;
    }

    public String getEndpoint() {
        return this.endpoint;
    }

    public String getKey() {
        return this.key;
    }

    public String getModelForAnalysis() {
        return this.model;
    }

    public String getModelForRenaming() {
        return config.getModelForRenaming();
    }

    public String getModelForRecursive() {
        return config.getModelForRecursive();
    }

    public double getTemperature() {
        return config.getModelTemperature();
    }

    public int getMaxTokens() {
        return config.getModelMaxTokens();
    }

    public boolean isRecursiveAnalysisEnabled() {
        return config.isRecursiveAnalysisEnabled();
    }

    public boolean isRecursiveRenamingEnabled() {
        return config.isRecursiveRenamingEnabled();
    }
}
