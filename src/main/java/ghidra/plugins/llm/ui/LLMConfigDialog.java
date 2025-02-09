package ghidra.plugins.llm.ui;

import java.awt.*;
import javax.swing.*;
import java.util.Properties;
import java.util.HashMap;
import java.util.Map;

import ghidra.util.Msg;
import ghidra.plugins.llm.config.ConfigManager;
import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.LLMProviderRegistry;
import ghidra.framework.plugintool.Plugin;
import ghidra.plugins.llm.LLMPlugin;
import ghidra.plugins.llm.ProjectContext;
import ghidra.plugins.llm.ui.config.*;

public class LLMConfigDialog extends JDialog {
    private final Plugin plugin;
    private final ConfigManager configManager;
    private final LLMProviderRegistry registry;
    private final ProviderManager providerManager;
    
    private ProviderConfigTab providerTab;
    private GeneralSettingsTab generalSettingsTab;
    private ProjectContextPanel projectContextPanel;

    public LLMConfigDialog(Frame parent, boolean modal, Plugin plugin) {
        super(parent, "LLM Configuration", modal);
        this.plugin = plugin;
        this.configManager = ConfigManager.getInstance();
        this.registry = LLMProviderRegistry.getInstance();
        this.providerManager = new ProviderManager(registry, configManager);
        
        setPreferredSize(new Dimension(800, 600));
        initComponents();
        loadCurrentConfig();
        setResizable(true);
        setLocationRelativeTo(parent);
        pack();
    }

    private void initComponents() {
        JTabbedPane tabbedPane = new JTabbedPane();

        // Initialize tabs
        providerTab = new ProviderConfigTab(unused -> updateProviderCombos());
        generalSettingsTab = new GeneralSettingsTab(unused -> {});
        projectContextPanel = new ProjectContextPanel();

        tabbedPane.addTab("Providers", providerTab);
        tabbedPane.addTab("General Settings", generalSettingsTab);
        tabbedPane.addTab("Project Context", projectContextPanel);

        // Dialog buttons
        JPanel dialogButtons = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton saveButton = new JButton("Save");
        JButton cancelButton = new JButton("Cancel");

        saveButton.addActionListener(e -> saveConfig());
        cancelButton.addActionListener(e -> dispose());

        dialogButtons.add(saveButton);
        dialogButtons.add(cancelButton);

        // Layout
        setLayout(new BorderLayout());
        JScrollPane scrollPane = new JScrollPane(tabbedPane);
        scrollPane.setPreferredSize(new Dimension(800, 550)); // Leave room for buttons
        add(scrollPane, BorderLayout.CENTER);
        add(dialogButtons, BorderLayout.SOUTH);
    }

    private void loadCurrentConfig() {
        // Load project context
        ProjectContext context = configManager.getProjectContext();
        if (context != null) {
            projectContextPanel.loadContext(context);
        }

        // Load providers
        String[] providerTypes = {
            ConfigLoaderUtils.AZURE_OPENAI_TYPE,
            ConfigLoaderUtils.AZURE_DEEPSEEK_TYPE,
            ConfigLoaderUtils.OPENAI_TYPE
        };

        for (String providerType : providerTypes) {
            ProviderConfigEntry entry = ConfigLoaderUtils.loadProviderFromConfig(providerType, configManager);
            if (entry != null) {
                providerTab.addProvider(entry);
            }
        }

        // Update provider combos
        updateProviderCombos();

        // Set default providers
        String defaultAnalysis = configManager.getDefaultAnalysisProvider();
        String defaultRenaming = configManager.getDefaultRenamingProvider();

        // Find display names for provider types
        String analysisDisplayName = getDisplayNameForProvider(defaultAnalysis);
        String renamingDisplayName = getDisplayNameForProvider(defaultRenaming);

        if (analysisDisplayName != null) {
            generalSettingsTab.setDefaultAnalysisProvider(analysisDisplayName);
        }
        if (renamingDisplayName != null) {
            generalSettingsTab.setDefaultRenamingProvider(renamingDisplayName);
        }
    }

    private void updateProviderCombos() {
        generalSettingsTab.updateProviders(providerTab.getProviderListModel());
    }

    private String getDisplayNameForProvider(String providerType) {
        if (providerType == null) return null;
        DefaultListModel<ProviderConfigEntry> model = providerTab.getProviderListModel();
        for (int i = 0; i < model.getSize(); i++) {
            ProviderConfigEntry entry = model.getElementAt(i);
            if (entry.name.equals(providerType)) {
                return entry.config.getDisplayName();
            }
        }
        return null;
    }

    private String getProviderTypeForDisplayName(String displayName) {
        if (displayName == null) return null;
        DefaultListModel<ProviderConfigEntry> model = providerTab.getProviderListModel();
        for (int i = 0; i < model.getSize(); i++) {
            ProviderConfigEntry entry = model.getElementAt(i);
            if (entry.config.getDisplayName().equals(displayName)) {
                return entry.name;
            }
        }
        return null;
    }

    private void saveConfig() {
        // Unregister existing providers
        providerManager.unregisterAllProviders();

        // Save each provider's config and re-register
        DefaultListModel<ProviderConfigEntry> model = providerTab.getProviderListModel();
        for (int i = 0; i < model.getSize(); i++) {
            ProviderConfigEntry entry = model.getElementAt(i);
            LLMConfig newConfig = entry.panel.getConfig();
            providerManager.saveAndRegisterProvider(entry.name, newConfig);
        }

        // Save general settings using internal names mapped from display names
        String analysisProvider = generalSettingsTab.getSelectedAnalysisProvider();
        String renamingProvider = generalSettingsTab.getSelectedRenamingProvider();
        
        String analysisType = getProviderTypeForDisplayName(analysisProvider);
        String renamingType = getProviderTypeForDisplayName(renamingProvider);

        if (analysisType != null) {
            configManager.setDefaultAnalysisProvider(analysisType);
        }
        if (renamingType != null) {
            configManager.setDefaultRenamingProvider(renamingType);
        }

        // Save project context
        ProjectContext context = projectContextPanel.getContext();
        configManager.setProjectContext(context);

        // Save all changes
        configManager.saveConfig();

        // Show confirmation
        Msg.info(this, "[LLM Config] Configuration saved successfully");

        // Close dialog
        dispose();
    }
}
