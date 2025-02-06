package ghidra.plugins.llm.providers.azure;

import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.config.ConfigManager;
import java.util.Properties;

/**
 * Configuration class for Azure Deepseek provider.
 */
public class AzureDeepseekConfig implements LLMConfig {
    private final ConfigManager config;
    private String endpoint;
    private String key;
    private String model;
    private String displayName;
    private double temperature = 0.7; // Default temperature
    private int maxTokens = 2000;    // Default max tokens

    public AzureDeepseekConfig() {
        this.config = ConfigManager.getInstance();
        Properties props = config.getProviderConfig("azure-deepseek");
        
        // Load values from config
        this.endpoint = props.getProperty("endpoint", "");
        this.key = props.getProperty("key", "");
        this.model = props.getProperty("analysis.model", "deepseek-r1");
        this.displayName = props.getProperty("display.name", "Azure Deepseek");
        try {
            this.temperature = Double.parseDouble(props.getProperty("temperature", "0.7"));
            this.maxTokens = Integer.parseInt(props.getProperty("max_tokens", "2000"));
        } catch (NumberFormatException e) {
            // Use defaults if parsing fails
            this.temperature = 0.7;
            this.maxTokens = 2000;
        }
    }

    public AzureDeepseekConfig(String endpoint, String key, String model, String displayName) {
        this.config = ConfigManager.getInstance();
        this.endpoint = endpoint;
        this.key = key;
        this.model = model;
        this.displayName = displayName != null ? displayName : "Azure Deepseek";
    }

    @Override
    public boolean isValid() {
        return endpoint != null && !endpoint.isEmpty() && 
               key != null && !key.isEmpty();
    }

    @Override
    public String getProviderType() {
        return "azure-deepseek";
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
        return this.temperature;
    }

    public int getMaxTokens() {
        return this.maxTokens;
    }

    public void setTemperature(double temperature) {
        this.temperature = temperature;
    }

    public void setMaxTokens(int maxTokens) {
        this.maxTokens = maxTokens;
    }

    public boolean isRecursiveAnalysisEnabled() {
        return config.isRecursiveAnalysisEnabled();
    }

    public boolean isRecursiveRenamingEnabled() {
        return config.isRecursiveRenamingEnabled();
    }
}
