package ghidra.plugins.llm.ui;

import java.awt.*;
import java.awt.event.*;
import javax.swing.*;
import java.util.Properties;

import ghidra.util.Msg;
import ghidra.plugins.llm.config.ConfigManager;
import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.LLMProviderRegistry;
import ghidra.plugins.llm.providers.azure.*;
import ghidra.framework.plugintool.Plugin;
import ghidra.plugins.llm.LLMPlugin;
import ghidra.plugins.llm.ProjectContext;

public class LLMConfigDialog extends JDialog {
    private final Plugin plugin;
    private final ConfigManager configManager;
    private final LLMProviderRegistry registry;
    private final ProviderManager providerManager;

    private DefaultListModel<ProviderConfigEntry> providerListModel;
    private JList<ProviderConfigEntry> providerList;
    private CardLayout providerCardLayout;
    private JPanel providerConfigPanel;
    private JComboBox<String> analysisProviderCombo;
    private JComboBox<String> renamingProviderCombo;
    private ProjectContextPanel projectContextPanel;

    private static class ProviderConfigEntry {
        final String name;
        final ProviderConfigPanel panel;
        final LLMConfig config;

        ProviderConfigEntry(String name, ProviderConfigPanel panel, LLMConfig config) {
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
        providerListModel = new DefaultListModel<>();
        projectContextPanel = new ProjectContextPanel();

        // Providers Tab
        JPanel providersPanel = new JPanel(new BorderLayout(10, 0));
        providersPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // Provider list on the left
        providerList = new JList<>(providerListModel);
        providerList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane listScroller = new JScrollPane(providerList);
        listScroller.setPreferredSize(new Dimension(200, 0));
        providersPanel.add(listScroller, BorderLayout.WEST);

        // Provider config panel on the right
        providerCardLayout = new CardLayout();
        providerConfigPanel = new JPanel(providerCardLayout);
        JScrollPane configScroll = new JScrollPane(providerConfigPanel);
        configScroll.setBorder(null);  // Remove border since panels have their own
        providersPanel.add(configScroll, BorderLayout.CENTER);

        // Provider buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addButton = new JButton("Add Provider");
        JButton removeButton = new JButton("Remove Provider");
        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);
        providersPanel.add(buttonPanel, BorderLayout.SOUTH);

        // Add provider button handler
        addButton.addActionListener(e -> {
            String[] options = { "Azure OpenAI", "Azure Deepseek" };
            String choice = (String) JOptionPane.showInputDialog(this,
                "Select provider type:", "Add Provider",
                JOptionPane.QUESTION_MESSAGE, null,
                options, options[0]);
            
                if (choice != null) {
                    // Generate default name for new provider
                    // Create panel and config based on provider type
                    ProviderConfigPanel panel;
                    LLMConfig config;
                    String providerType;
                    String displayName;
                    
                    if (choice.equals("Azure OpenAI")) {
                        providerType = AZURE_OPENAI_TYPE;
                        displayName = "Azure OpenAI";
                        panel = new AzureOpenAIConfigPanel();
                        config = new AzureConfig(null, null, null, displayName);
                    } else {
                        providerType = AZURE_DEEPSEEK_TYPE;
                        displayName = "Azure Deepseek";
                        panel = new AzureDeepseekConfigPanel();
                        config = new AzureDeepseekConfig(null, null, null, displayName);
                    }

                    // Set the name in the panel and add a listener for name changes
                    panel.nameField.setText(displayName);
                    panel.nameField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
                        private void updateName() {
                            // Update config and refresh UI
                            String newName = panel.nameField.getText().trim();
                            if (config != null) {
                                config.setDisplayName(newName);
                                // Force list and combo boxes to update
                                providerList.repaint();
                                updateProviderCombos();
                            }
                        }
                        public void insertUpdate(javax.swing.event.DocumentEvent e) { updateName(); }
                        public void removeUpdate(javax.swing.event.DocumentEvent e) { updateName(); }
                        public void changedUpdate(javax.swing.event.DocumentEvent e) { updateName(); }
                    });

                ProviderConfigEntry entry = new ProviderConfigEntry(providerType, panel, config);
                providerListModel.addElement(entry);
                providerConfigPanel.add(panel, providerType);
                providerList.setSelectedValue(entry, true);
            }
        });

        // Remove provider button handler
        removeButton.addActionListener(e -> {
            int index = providerList.getSelectedIndex();
            if (index != -1) {
                ProviderConfigEntry entry = providerListModel.getElementAt(index);
                providerListModel.remove(index);
                providerConfigPanel.remove(entry.panel);
                revalidate();
                repaint();
            }
        });

        // Provider selection handler
        providerList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                ProviderConfigEntry selected = providerList.getSelectedValue();
                if (selected != null) {
                    providerCardLayout.show(providerConfigPanel, selected.name);
                }
            }
        });

        tabbedPane.addTab("Providers", providersPanel);

        // General Settings Tab
        JPanel generalPanel = new JPanel(new GridBagLayout());
        generalPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        gbc.gridx = 0;
        gbc.gridy = 0;
        generalPanel.add(new JLabel("Default Analysis Provider:"), gbc);
        gbc.gridx = 1;
        analysisProviderCombo = new JComboBox<>();
        generalPanel.add(analysisProviderCombo, gbc);

        gbc.gridx = 0;
        gbc.gridy++;
        generalPanel.add(new JLabel("Default Renaming Provider:"), gbc);
        gbc.gridx = 1;
        renamingProviderCombo = new JComboBox<>();
        generalPanel.add(renamingProviderCombo, gbc);

        tabbedPane.addTab("General Settings", generalPanel);
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
        scrollPane.setPreferredSize(new Dimension(800, 550));  // Leave room for buttons
        add(scrollPane, BorderLayout.CENTER);
        add(dialogButtons, BorderLayout.SOUTH);
    }

    private String generateUniqueName(String baseName) {
        // Start with just the base name
        String candidateName = baseName;
        int suffix = 1;
        
        // Keep incrementing suffix until we find a unique name
        while (isNameTaken(candidateName)) {
            suffix++;
            candidateName = baseName + " " + suffix;
        }
        
        return candidateName;
    }
    
    private boolean isNameTaken(String name) {
        for (int i = 0; i < providerListModel.getSize(); i++) {
            if (providerListModel.getElementAt(i).name.equals(name)) {
                return true;
            }
        }
        return false;
    }

    private static final String AZURE_OPENAI_TYPE = "azure-openai";
    private static final String AZURE_DEEPSEEK_TYPE = "azure-deepseek";

    private void loadCurrentConfig() {
        // Load project context
        ProjectContext context = configManager.getProjectContext();
        if (context != null) {
            projectContextPanel.loadContext(context);
        }

        // Load Azure OpenAI provider
        Properties props = configManager.getProviderConfig(AZURE_OPENAI_TYPE);
        if (!props.isEmpty()) {
            loadProviderFromConfig(AZURE_OPENAI_TYPE);
        }

        // Load Azure Deepseek provider
        props = configManager.getProviderConfig(AZURE_DEEPSEEK_TYPE);
        if (!props.isEmpty()) {
            loadProviderFromConfig(AZURE_DEEPSEEK_TYPE);
        }

        // Select first provider
        if (providerListModel.getSize() > 0) {
            providerList.setSelectedIndex(0);
        }

        // Update combo boxes
        updateProviderCombos();

        // Set default selections - map from internal names to display names
        String defaultAnalysis = configManager.getDefaultAnalysisProvider();
        String defaultRenaming = configManager.getDefaultRenamingProvider();
        
        // Find the provider configs and use their display names
        for (int i = 0; i < providerListModel.getSize(); i++) {
            ProviderConfigEntry entry = providerListModel.getElementAt(i);
            if (entry.name.equals(defaultAnalysis)) {
                analysisProviderCombo.setSelectedItem(entry.config.getDisplayName());
            }
            if (entry.name.equals(defaultRenaming)) {
                renamingProviderCombo.setSelectedItem(entry.config.getDisplayName());
            }
        }
    }

    private void loadProviderFromConfig(String providerName) {
        Properties props = configManager.getProviderConfig(providerName);
        if (props.isEmpty()) {
            Msg.debug(this, "[LLM Config] No config found for: " + providerName);
            return;
        }

        Msg.debug(this, "[LLM Config] Loading config for " + providerName + ": " + props);
        
        if (providerName.equals(AZURE_OPENAI_TYPE)) {
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
                ProviderConfigEntry entry = new ProviderConfigEntry(providerName, panel, config);
                providerListModel.addElement(entry);
                providerConfigPanel.add(panel, providerName);
                Msg.debug(this, "[LLM Config] Added OpenAI provider: " + config.getEndpoint());
            }
        } else if (providerName.equals(AZURE_DEEPSEEK_TYPE)) {
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
                Msg.debug(this, "[LLM Config] Error parsing Deepseek numeric properties: " + e.getMessage());
            }
            
            if (config.isValid()) {
                panel.loadConfig(config);
                ProviderConfigEntry entry = new ProviderConfigEntry(providerName, panel, config);
                providerListModel.addElement(entry);
                providerConfigPanel.add(panel, providerName);
                Msg.debug(this, "[LLM Config] Added Deepseek provider: " + config.getEndpoint());
            }
        }
    }

    private void updateProviderCombos() {
        analysisProviderCombo.removeAllItems();
        renamingProviderCombo.removeAllItems();

        for (int i = 0; i < providerListModel.getSize(); i++) {
            ProviderConfigEntry entry = providerListModel.getElementAt(i);
            String displayName = entry.config.getDisplayName();
            analysisProviderCombo.addItem(displayName);
            renamingProviderCombo.addItem(displayName);
        }

        // Update selections if they were previously set
        String defaultAnalysisProvider = configManager.getDefaultAnalysisProvider();
        String defaultRenamingProvider = configManager.getDefaultRenamingProvider();
        
        if (analysisProviderCombo.getSelectedItem() == null && defaultAnalysisProvider != null) {
            // Find provider by internal name and use its display name
            for (int i = 0; i < providerListModel.getSize(); i++) {
                ProviderConfigEntry entry = providerListModel.getElementAt(i);
                if (entry.name.equals(defaultAnalysisProvider)) {
                    analysisProviderCombo.setSelectedItem(entry.config.getDisplayName());
                    break;
                }
            }
        }
        if (renamingProviderCombo.getSelectedItem() == null && defaultRenamingProvider != null) {
            // Find provider by internal name and use its display name
            for (int i = 0; i < providerListModel.getSize(); i++) {
                ProviderConfigEntry entry = providerListModel.getElementAt(i);
                if (entry.name.equals(defaultRenamingProvider)) {
                    renamingProviderCombo.setSelectedItem(entry.config.getDisplayName());
                    break;
                }
            }
        }
    }

    private void saveConfig() {
        // Unregister existing providers
        providerManager.unregisterAllProviders();

        // Create map of display names to provider entries
        java.util.Map<String, ProviderConfigEntry> displayNameMap = new java.util.HashMap<>();
        for (int i = 0; i < providerListModel.getSize(); i++) {
            ProviderConfigEntry entry = providerListModel.getElementAt(i);
            displayNameMap.put(entry.config.getDisplayName(), entry);
        }

        // Save each provider's config and re-register
        for (int i = 0; i < providerListModel.getSize(); i++) {
            ProviderConfigEntry entry = providerListModel.getElementAt(i);
            LLMConfig newConfig = entry.panel.getConfig();
            providerManager.saveAndRegisterProvider(entry.name, newConfig);
        }

        // Save general settings using internal names mapped from display names
        String selectedAnalysisDisplay = (String)analysisProviderCombo.getSelectedItem();
        String selectedRenamingDisplay = (String)renamingProviderCombo.getSelectedItem();
        
        String selectedAnalysis = selectedAnalysisDisplay;
        String selectedRenaming = selectedRenamingDisplay;
        if (selectedAnalysisDisplay != null && displayNameMap.containsKey(selectedAnalysisDisplay)) {
            selectedAnalysis = displayNameMap.get(selectedAnalysisDisplay).name;
        }
        if (selectedRenamingDisplay != null && displayNameMap.containsKey(selectedRenamingDisplay)) {
            selectedRenaming = displayNameMap.get(selectedRenamingDisplay).name;
        }
        if (selectedAnalysis != null) {
            configManager.setDefaultAnalysisProvider(selectedAnalysis);
        }
        if (selectedRenaming != null) {
            configManager.setDefaultRenamingProvider(selectedRenaming);
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
