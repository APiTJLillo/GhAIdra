package ghidra.plugins.llm.ui.config;

import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.ui.ProviderConfigPanel;

/**
 * Container class for provider configuration entries.
 * Links together the provider's name, configuration panel, and settings.
 */
public class ProviderConfigEntry {
    public final String name;
    public final ProviderConfigPanel panel;
    public final LLMConfig config;

    public ProviderConfigEntry(String name, ProviderConfigPanel panel, LLMConfig config) {
        this.name = name;
        this.panel = panel;
        this.config = config;
    }

    @Override
    public String toString() {
        // Use the display name from config if available, otherwise fall back to internal name
        return config != null ? config.getDisplayName() : name;
    }
}
