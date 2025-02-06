package ghidra.plugins.llm;

import java.util.Map;
import java.util.HashMap;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry for managing LLM providers and their configurations.
 */
public class LLMProviderRegistry {
    private static LLMProviderRegistry instance;
    private final Map<String, LLMProvider> providers;
    private final Map<String, LLMConfig> configurations;

    private LLMProviderRegistry() {
        this.providers = new ConcurrentHashMap<>();
        this.configurations = new ConcurrentHashMap<>();
    }

    /**
     * Gets the singleton instance of the registry.
     */
    public static synchronized LLMProviderRegistry getInstance() {
        if (instance == null) {
            instance = new LLMProviderRegistry();
        }
        return instance;
    }

    /**
     * Registers a new provider with its configuration.
     * @param provider the provider implementation
     * @param config the provider's configuration
     */
    public void registerProvider(LLMProvider provider, LLMConfig config) {
        if (!config.isValid()) {
            throw new IllegalArgumentException("Invalid configuration for provider: " + config.getProviderType());
        }
        
        String type = config.getProviderType();
        providers.put(type, provider);
        configurations.put(type, config);
        provider.configure(config);
    }

    /**
     * Gets a provider by its type.
     * @param type the provider type identifier
     * @return the provider instance
     */
    public LLMProvider getProvider(String type) {
        LLMProvider provider = providers.get(type);
        if (provider == null) {
            throw new IllegalArgumentException("No provider registered for type: " + type);
        }
        return provider;
    }

    /**
     * Gets a provider's configuration.
     * @param type the provider type identifier
     * @return the provider's configuration
     */
    public LLMConfig getConfiguration(String type) {
        LLMConfig config = configurations.get(type);
        if (config == null) {
            throw new IllegalArgumentException("No configuration found for provider type: " + type);
        }
        return config;
    }

    /**
     * Gets all registered provider types.
     * @return set of provider type identifiers
     */
    public Set<String> getProviderTypes() {
        return providers.keySet();
    }

    /**
     * Updates a provider's configuration.
     * @param type the provider type identifier
     * @param config the new configuration
     */
    public void updateConfiguration(String type, LLMConfig config) {
        if (!config.isValid()) {
            throw new IllegalArgumentException("Invalid configuration for provider: " + type);
        }
        
        LLMProvider provider = getProvider(type);
        configurations.put(type, config);
        provider.configure(config);
    }

    /**
     * Removes a provider and its configuration.
     * @param type the provider type identifier
     */
    public void unregisterProvider(String type) {
        LLMProvider provider = providers.remove(type);
        if (provider != null) {
            provider.dispose();
        }
        configurations.remove(type);
    }

    /**
     * Disposes of all providers and clears the registry.
     */
    public void dispose() {
        providers.values().forEach(LLMProvider::dispose);
        providers.clear();
        configurations.clear();
    }
}
