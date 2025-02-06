package ghidra.plugins.llm.ui;

import java.util.Properties;
import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.LLMProviderRegistry;
import ghidra.plugins.llm.config.ConfigManager;
import ghidra.plugins.llm.providers.azure.*;
import ghidra.util.Msg;

public class ProviderManager {
    private final LLMProviderRegistry registry;
    private final ConfigManager configManager;
    
    private static final String AZURE_OPENAI_TYPE = "azure-openai";
    private static final String AZURE_DEEPSEEK_TYPE = "azure-deepseek";

    public ProviderManager(LLMProviderRegistry registry, ConfigManager configManager) {
        this.registry = registry;
        this.configManager = configManager;
    }

    public void saveAndRegisterProvider(String providerName, LLMConfig newConfig) {
        try {
            Msg.debug(this, "[LLM Config] Saving provider config for: " + providerName);
            Properties config = new Properties();

            // Common properties for all LLM configs
            config.setProperty("display.name", newConfig.getDisplayName());

            // Save properties based on config type
            if (newConfig instanceof AzureDeepseekConfig) {
                AzureDeepseekConfig deepseekConfig = (AzureDeepseekConfig) newConfig;
                // Save Deepseek specific properties
                config.setProperty("temperature", String.valueOf(deepseekConfig.getTemperature()));
                config.setProperty("max_tokens", String.valueOf(deepseekConfig.getMaxTokens()));
                // Save inherited Azure properties
                config.setProperty("endpoint", deepseekConfig.getEndpoint());
                config.setProperty("key", deepseekConfig.getKey());
                config.setProperty("analysis.model", deepseekConfig.getModelForAnalysis());
                
                Msg.debug(this, "[LLM Config] Saving Deepseek config: " + config);
            }
            else if (newConfig instanceof AzureConfig) {
                AzureConfig azureConfig = (AzureConfig) newConfig;
                config.setProperty("endpoint", azureConfig.getEndpoint());
                config.setProperty("key", azureConfig.getKey());
                config.setProperty("analysis.model", azureConfig.getModelForAnalysis());
                
                Msg.debug(this, "[LLM Config] Saving Azure config: " + config);
            }

            Msg.debug(this, "[LLM Config] Setting provider config: " + config);
            configManager.setProviderConfig(providerName, config);
            configManager.saveConfig();

            // Re-register provider with current config
            Properties savedConfig = configManager.getProviderConfig(providerName);
            Msg.debug(this, "[LLM Config] Retrieved saved config for " + providerName + ": " + savedConfig);
            
            String displayName = savedConfig.getProperty("display.name", providerName);
            String savedEndpoint = savedConfig.getProperty("endpoint", "");
            String savedKey = savedConfig.getProperty("key", "");
            String savedModel = savedConfig.getProperty("analysis.model", "");
            
            if (providerName.equals(AZURE_OPENAI_TYPE)) {
                AzureConfig providerConfig = new AzureConfig(savedEndpoint, savedKey, savedModel, displayName);
                if (providerConfig.isValid()) {
                    registry.registerProvider(new AzureOpenAIProvider(), providerConfig);
                    Msg.debug(this, "[LLM Config] Registered OpenAI provider with endpoint: " + savedEndpoint);
                } else {
                    Msg.error(this, "[LLM Config] Invalid Azure OpenAI config: " + providerConfig);
                }
            } else if (providerName.equals(AZURE_DEEPSEEK_TYPE)) {
                AzureDeepseekConfig providerConfig = new AzureDeepseekConfig(savedEndpoint, savedKey, savedModel, displayName);
                
                String tempStr = savedConfig.getProperty("temperature");
                if (tempStr != null) {
                    providerConfig.setTemperature(Double.parseDouble(tempStr));
                }
                
                String tokensStr = savedConfig.getProperty("max_tokens");
                if (tokensStr != null) {
                    providerConfig.setMaxTokens(Integer.parseInt(tokensStr));
                }
                
                if (providerConfig.isValid()) {
                    registry.registerProvider(new AzureDeepseekProvider(), providerConfig);
                    Msg.debug(this, "[LLM Config] Registered Deepseek provider with endpoint: " + savedEndpoint);
                } else {
                    Msg.error(this, "[LLM Config] Invalid Deepseek config: " + providerConfig);
                }
            }
        } catch (Exception e) {
            Msg.error(this, "[LLM Config] Error saving/registering provider: " + e.getMessage(), e);
        }
    }

    public void unregisterAllProviders() {
        for (String type : registry.getProviderTypes()) {
            Msg.debug(this, "[LLM Config] Unregistering provider: " + type);
            registry.unregisterProvider(type);
        }
    }
}
