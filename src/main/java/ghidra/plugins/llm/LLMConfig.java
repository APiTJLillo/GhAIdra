package ghidra.plugins.llm;

/**
 * Interface for LLM provider configurations.
 * Each provider will have its own implementation of this interface.
 */
public interface LLMConfig {
    /**
     * Validates the configuration.
     * @return true if the configuration is valid, false otherwise
     */
    boolean isValid();

    /**
     * Gets the unique identifier for this provider type.
     * @return The provider type identifier (e.g., "azure", "ollama")
     */
    String getProviderType();
    
    /**
     * Gets a user-friendly name for the provider.
     * @return The display name for the provider
     */
    String getDisplayName();
    
    /**
     * Sets the user-friendly display name for the provider.
     * @param name The new display name
     */
    void setDisplayName(String name);
}
