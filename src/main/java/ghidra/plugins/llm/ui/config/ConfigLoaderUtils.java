package ghidra.plugins.llm.ui.config;

import java.util.Properties;
import ghidra.util.Msg;
import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.config.ConfigManager;
import ghidra.plugins.llm.providers.azure.*;
import ghidra.plugins.llm.providers.openai.*;
import ghidra.plugins.llm.providers.anthropic.*;
import ghidra.plugins.llm.ui.*;

public class ConfigLoaderUtils {
    public static final String AZURE_OPENAI_TYPE = "azure-openai";
    public static final String AZURE_DEEPSEEK_TYPE = "azure-deepseek";
    public static final String OPENAI_TYPE = "openai";
    public static final String ANTHROPIC_TYPE = "anthropic";

    public static ProviderConfigEntry loadProviderFromConfig(String providerName, ConfigManager configManager) {
        Properties props = configManager.getProviderConfig(providerName);
        if (props.isEmpty()) {
            Msg.debug(ConfigLoaderUtils.class, "[LLM Config] No config found for: " + providerName);
            return null;
        }

        Msg.debug(ConfigLoaderUtils.class, "[LLM Config] Loading config for " + providerName + ": " + props);
        
        if (providerName.equals(AZURE_OPENAI_TYPE)) {
            return loadAzureOpenAIConfig(props, providerName);
        } else if (providerName.equals(AZURE_DEEPSEEK_TYPE)) {
            return loadAzureDeepseekConfig(props, providerName);
        } else if (providerName.equals(OPENAI_TYPE)) {
            return loadOpenAIConfig(props, providerName);
        } else if (providerName.equals(ANTHROPIC_TYPE)) {
            return loadAnthropicConfig(props, providerName);
        }
        
        return null;
    }

    private static ProviderConfigEntry loadAzureOpenAIConfig(Properties props, String providerName) {
        AzureOpenAIConfigPanel panel = new AzureOpenAIConfigPanel();
        String displayName = props.getProperty(providerName + ".display.name", providerName);
        AzureConfig config = new AzureConfig(
            props.getProperty("endpoint", ""),
            props.getProperty("key", ""),
            props.getProperty("analysis.model", ""),
            displayName
        );
        
        if (config.isValid()) {
            panel.loadConfig(config);
            return new ProviderConfigEntry(providerName, panel, config);
        }
        return null;
    }

    private static ProviderConfigEntry loadAzureDeepseekConfig(Properties props, String providerName) {
        AzureDeepseekConfigPanel panel = new AzureDeepseekConfigPanel();
        String displayName = props.getProperty("display.name", providerName);
        AzureDeepseekConfig config = new AzureDeepseekConfig(
            props.getProperty("endpoint", ""),
            props.getProperty("key", ""),
            props.getProperty("analysis.model", "deepseek-r1"),
            displayName
        );
        
        try {
            String tempStr = props.getProperty("temperature");
            if (tempStr != null) {
                config.setTemperature(Double.parseDouble(tempStr));
            }
            
            String tokensStr = props.getProperty("max_tokens");
            if (tokensStr != null) {
                config.setMaxTokens(Integer.parseInt(tokensStr));
            }
        } catch (NumberFormatException e) {
            Msg.debug(ConfigLoaderUtils.class, "[LLM Config] Error parsing Deepseek numeric properties: " + e.getMessage());
        }
        
        if (config.isValid()) {
            panel.loadConfig(config);
            return new ProviderConfigEntry(providerName, panel, config);
        }
        return null;
    }

    private static ProviderConfigEntry loadOpenAIConfig(Properties props, String providerName) {
        OpenAIConfigPanel panel = new OpenAIConfigPanel();
        String displayName = props.getProperty("display.name", providerName);
        OpenAIConfig config = new OpenAIConfig();
        config.setDisplayName(displayName);
        config.setApiKey(props.getProperty("api.key", ""));
        config.setModel(props.getProperty("model", "gpt-4-turbo-preview"));
        
        try {
            String tempStr = props.getProperty("temperature");
            if (tempStr != null) {
                config.setTemperature(Double.parseDouble(tempStr));
            }
            
            String tokensStr = props.getProperty("max_tokens");
            if (tokensStr != null) {
                config.setMaxTokens(Integer.parseInt(tokensStr));
            }
        } catch (NumberFormatException e) {
            Msg.debug(ConfigLoaderUtils.class, "[LLM Config] Error parsing OpenAI numeric properties: " + e.getMessage());
        }
        
        if (config.isValid()) {
            panel.loadConfig(config);
            return new ProviderConfigEntry(providerName, panel, config);
        }
        return null;
    }

    private static ProviderConfigEntry loadAnthropicConfig(Properties props, String providerName) {
        AnthropicConfigPanel panel = new AnthropicConfigPanel();
        String displayName = props.getProperty("display.name", providerName);
        AnthropicConfig config = new AnthropicConfig();
        config.setDisplayName(displayName);
        config.setApiKey(props.getProperty("api.key", ""));
        config.setModel(props.getProperty("model", "claude-3-opus-20240229"));
        
        try {
            String tempStr = props.getProperty("temperature");
            if (tempStr != null) {
                config.setTemperature(Double.parseDouble(tempStr));
            }
            
            String tokensStr = props.getProperty("max_tokens");
            if (tokensStr != null) {
                config.setMaxTokens(Integer.parseInt(tokensStr));
            }
        } catch (NumberFormatException e) {
            Msg.debug(ConfigLoaderUtils.class, "[LLM Config] Error parsing Anthropic numeric properties: " + e.getMessage());
        }
        
        if (config.isValid()) {
            panel.loadConfig(config);
            return new ProviderConfigEntry(providerName, panel, config);
        }
        return null;
    }
}
