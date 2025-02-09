package ghidra.plugins.llm.providers.anthropic;

import ghidra.plugins.llm.LLMConfig;

public class AnthropicConfig implements LLMConfig {
    private String displayName;
    private String apiKey;
    private String model;
    private double temperature;
    private int maxTokens;
    private boolean enabled;

    public AnthropicConfig() {
        this.displayName = "Anthropic";
        this.model = "claude-3-opus-20240229";  // Latest model as of 2024
        this.temperature = 0.7;
        this.maxTokens = 2048;
        this.enabled = true;
    }

    @Override
    public boolean isValid() {
        return apiKey != null && !apiKey.trim().isEmpty() &&
               model != null && !model.trim().isEmpty();
    }

    @Override
    public String getProviderType() {
        return "anthropic";
    }

    @Override
    public String getDisplayName() {
        return displayName;
    }

    @Override
    public void setDisplayName(String name) {
        this.displayName = name;
    }

    public String getApiKey() {
        return apiKey;
    }

    public void setApiKey(String apiKey) {
        this.apiKey = apiKey;
    }

    public String getModel() {
        return model;
    }

    public void setModel(String model) {
        this.model = model;
    }

    public double getTemperature() {
        return temperature;
    }

    public void setTemperature(double temperature) {
        this.temperature = temperature;
    }

    public int getMaxTokens() {
        return maxTokens;
    }

    public void setMaxTokens(int maxTokens) {
        this.maxTokens = maxTokens;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
