package ghidra.plugins.llm.config;

import java.io.*;
import java.util.*;
import java.util.Properties;

import ghidra.framework.Application;

public class ConfigManager {
    private static final String CONFIG_FILE_NAME = "azure_config.properties";
    private static ConfigManager instance;
    private Properties properties;
    private String defaultAnalysisProvider;
    private String defaultRenamingProvider;
    private Map<String, Properties> providerConfigs;

    private ConfigManager() {
        properties = new Properties();
        providerConfigs = new HashMap<>();
        loadConfig();
    }

    public static synchronized ConfigManager getInstance() {
        if (instance == null) {
            instance = new ConfigManager();
        }
        return instance;
    }

    private void loadConfig() {
        try {
            File configFile = new File(Application.getUserSettingsDirectory(), CONFIG_FILE_NAME);
            if (configFile.exists()) {
                try (FileInputStream fis = new FileInputStream(configFile)) {
                    properties.load(fis);
                }
            }
            defaultAnalysisProvider = properties.getProperty("default.analysis.provider", "azure-openai");
            defaultRenamingProvider = properties.getProperty("default.renaming.provider", "azure-openai");
            
            // Load initial provider configs
            loadAllProviderConfigs();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void loadAllProviderConfigs() {
        Set<String> foundProviders = new HashSet<>();
        
        // Find all providers by looking for display.name properties
        for (String key : properties.stringPropertyNames()) {
            if (key.endsWith(".display.name")) {
                String providerName = key.substring(0, key.length() - ".display.name".length());
                foundProviders.add(providerName);
            }
        }
        
        // Load each provider's properties
        for (String providerName : foundProviders) {
            Properties providerProps = new Properties();
            String searchName = providerName + ".";
            
            for (String key : properties.stringPropertyNames()) {
                if (key.startsWith(searchName)) {
                    providerProps.setProperty(
                        key.substring(searchName.length()), // Store without provider prefix
                        properties.getProperty(key)
                    );
                }
            }
            
            if (!providerProps.isEmpty()) {
                providerConfigs.put(providerName, providerProps);
            }
        }
    }

    public void saveConfig() {
        try {
            Properties newProperties = new Properties();

            // First save default settings
            newProperties.setProperty("default.analysis.provider", defaultAnalysisProvider);
            newProperties.setProperty("default.renaming.provider", defaultRenamingProvider);

            // Save provider configs with provider name prefix
            for (Map.Entry<String, Properties> entry : providerConfigs.entrySet()) {
                String providerName = entry.getKey();
                Properties providerProps = entry.getValue();
                
                // Debug log for provider saving
                System.out.println("[Config Debug] Saving provider: " + providerName);
                System.out.println("[Config Debug] Properties: " + providerProps.toString());
                
                for (String key : providerProps.stringPropertyNames()) {
                    String fullKey = providerName + "." + key;
                    String value = providerProps.getProperty(key);
                    newProperties.setProperty(fullKey, value);
                    System.out.println("[Config Debug] Setting: " + fullKey + " = " + value);
                }
            }

            // Update main properties
            properties.clear();
            properties.putAll(newProperties);

            File configFile = new File(Application.getUserSettingsDirectory(), CONFIG_FILE_NAME);
            try (FileOutputStream fos = new FileOutputStream(configFile)) {
                properties.store(fos, "LLM Plugin Configuration");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getDefaultAnalysisProvider() {
        return defaultAnalysisProvider;
    }

    public void setDefaultAnalysisProvider(String provider) {
        this.defaultAnalysisProvider = provider;
    }

    public String getDefaultRenamingProvider() {
        return defaultRenamingProvider;
    }

    public void setDefaultRenamingProvider(String provider) {
        this.defaultRenamingProvider = provider;
    }

    public Properties getProviderConfig(String providerName) {
        return providerConfigs.getOrDefault(providerName, new Properties());
    }

    public void setProviderConfig(String providerName, Properties config) {
        providerConfigs.put(providerName, config);
    }

    // Legacy methods for backward compatibility
    public String getAzureEndpoint() {
        Properties props = getProviderConfig("azure-openai");
        return props.getProperty("endpoint", "");
    }

    public void setAzureEndpoint(String endpoint) {
        Properties config = getProviderConfig("azure-openai");
        config.setProperty("endpoint", endpoint);
        setProviderConfig("azure-openai", config);
    }

    public String getAzureKey() {
        Properties props = getProviderConfig("azure-openai");
        return props.getProperty("key", "");
    }

    public void setAzureKey(String key) {
        Properties config = getProviderConfig("azure-openai");
        config.setProperty("key", key);
        setProviderConfig("azure-openai", config);
    }

    public String getModelForAnalysis() {
        Properties props = getProviderConfig("azure-openai");
        return props.getProperty("analysis.model", "");
    }

    public void setModelForAnalysis(String model) {
        Properties config = getProviderConfig("azure-openai");
        config.setProperty("analysis.model", model);
        setProviderConfig("azure-openai", config);
    }

    public String getModelForRenaming() {
        Properties props = getProviderConfig("azure-openai");
        return props.getProperty("renaming.model", "");
    }

    public void setModelForRenaming(String model) {
        Properties config = getProviderConfig("azure-openai");
        config.setProperty("renaming.model", model);
        setProviderConfig("azure-openai", config);
    }

    public String getModelForRecursive() {
        Properties props = getProviderConfig("azure-openai");
        return props.getProperty("recursive.model", "");
    }

    public void setModelForRecursive(String model) {
        Properties config = getProviderConfig("azure-openai");
        config.setProperty("recursive.model", model);
        setProviderConfig("azure-openai", config);
    }

    public double getModelTemperature() {
        Properties props = getProviderConfig("azure-openai");
        String temp = props.getProperty("temperature", "0.7");
        return Double.parseDouble(temp);
    }

    public void setModelTemperature(double temperature) {
        Properties config = getProviderConfig("azure-openai");
        config.setProperty("temperature", String.valueOf(temperature));
        setProviderConfig("azure-openai", config);
    }

    public int getModelMaxTokens() {
        Properties props = getProviderConfig("azure-openai");
        String tokens = props.getProperty("max.tokens", "2000");
        return Integer.parseInt(tokens);
    }

    public void setModelMaxTokens(int maxTokens) {
        Properties config = getProviderConfig("azure-openai");
        config.setProperty("max.tokens", String.valueOf(maxTokens));
        setProviderConfig("azure-openai", config);
    }

    public boolean isRecursiveAnalysisEnabled() {
        Properties props = getProviderConfig("azure-openai");
        return Boolean.parseBoolean(props.getProperty("recursive.analysis.enabled", "false"));
    }

    public void setRecursiveAnalysisEnabled(boolean enabled) {
        Properties config = getProviderConfig("azure-openai");
        config.setProperty("recursive.analysis.enabled", String.valueOf(enabled));
        setProviderConfig("azure-openai", config);
    }

    public boolean isRecursiveRenamingEnabled() {
        Properties props = getProviderConfig("azure-openai");
        return Boolean.parseBoolean(props.getProperty("recursive.renaming.enabled", "false"));
    }

    public void setRecursiveRenamingEnabled(boolean enabled) {
        Properties config = getProviderConfig("azure-openai");
        config.setProperty("recursive.renaming.enabled", String.valueOf(enabled));
        setProviderConfig("azure-openai", config);
    }
}
