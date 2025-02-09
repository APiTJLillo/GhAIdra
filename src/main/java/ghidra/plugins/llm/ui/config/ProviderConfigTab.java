package ghidra.plugins.llm.ui.config;

import javax.swing.*;
import java.awt.*;
import java.util.function.Consumer;

import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.ui.*;
import ghidra.plugins.llm.providers.azure.*;
import ghidra.plugins.llm.providers.openai.*;
import ghidra.plugins.llm.providers.anthropic.*;

/**
 * Tab panel for managing LLM provider configurations.
 */
public class ProviderConfigTab extends JPanel {
    private DefaultListModel<ProviderConfigEntry> providerListModel;
    private JList<ProviderConfigEntry> providerList;
    private CardLayout providerCardLayout;
    private JPanel providerConfigPanel;
    private Consumer<Void> onConfigChanged;

    public ProviderConfigTab(Consumer<Void> onConfigChanged) {
        this.onConfigChanged = onConfigChanged;
        setLayout(new BorderLayout(10, 0));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        initializeComponents();
    }

    private void initializeComponents() {
        providerListModel = new DefaultListModel<>();

        // Provider list on the left
        providerList = new JList<>(providerListModel);
        providerList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane listScroller = new JScrollPane(providerList);
        listScroller.setPreferredSize(new Dimension(200, 0));
        add(listScroller, BorderLayout.WEST);

        // Provider config panel on the right
        providerCardLayout = new CardLayout();
        providerConfigPanel = new JPanel(providerCardLayout);
        JScrollPane configScroll = new JScrollPane(providerConfigPanel);
        configScroll.setBorder(null);  // Remove border since panels have their own
        add(configScroll, BorderLayout.CENTER);

        // Provider buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addButton = new JButton("Add Provider");
        JButton removeButton = new JButton("Remove Provider");
        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);
        add(buttonPanel, BorderLayout.SOUTH);

        // Add provider button handler
        addButton.addActionListener(e -> {
            String[] options = { "Azure OpenAI", "Azure Deepseek", "OpenAI", "Anthropic" };
            String choice = (String) JOptionPane.showInputDialog(this,
                "Select provider type:", "Add Provider",
                JOptionPane.QUESTION_MESSAGE, null,
                options, options[0]);
            
            if (choice != null) {
                addNewProvider(choice);
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
                onConfigChanged.accept(null);
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
    }

    private void addNewProvider(String choice) {
        // Create panel and config based on provider type
        ProviderConfigPanel panel;
        LLMConfig config;
        String providerType;
        String displayName;
        
        if (choice.equals("Azure OpenAI")) {
            providerType = ConfigLoaderUtils.AZURE_OPENAI_TYPE;
            displayName = generateUniqueName("Azure OpenAI");
            panel = new AzureOpenAIConfigPanel();
            config = new AzureConfig(null, null, null, displayName);
        } else if (choice.equals("Azure Deepseek")) {
            providerType = ConfigLoaderUtils.AZURE_DEEPSEEK_TYPE;
            displayName = generateUniqueName("Azure Deepseek");
            panel = new AzureDeepseekConfigPanel();
            config = new AzureDeepseekConfig(null, null, null, displayName);
        } else if (choice.equals("OpenAI")) {
            providerType = ConfigLoaderUtils.OPENAI_TYPE;
            displayName = generateUniqueName("OpenAI");
            panel = new OpenAIConfigPanel();
            config = new OpenAIConfig();
            config.setDisplayName(displayName);
        } else { // Anthropic
            providerType = ConfigLoaderUtils.ANTHROPIC_TYPE;
            displayName = generateUniqueName("Anthropic");
            panel = new AnthropicConfigPanel();
            config = new AnthropicConfig();
            config.setDisplayName(displayName);
        }

        // Set the name in the panel and add a listener for name changes
        panel.setProviderName(displayName);
        panel.addNameChangeListener(new javax.swing.event.DocumentListener() {
            private void updateName() {
                // Update config and refresh UI
                String newName = panel.getProviderName();
                if (config != null) {
                    config.setDisplayName(newName);
                    // Force list to update
                    providerList.repaint();
                    onConfigChanged.accept(null);
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
        onConfigChanged.accept(null);
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
            ProviderConfigEntry entry = providerListModel.getElementAt(i);
            if (entry.config.getDisplayName().equals(name)) {
                return true;
            }
        }
        return false;
    }

    public void addProvider(ProviderConfigEntry entry) {
        if (entry != null) {
            providerListModel.addElement(entry);
            providerConfigPanel.add(entry.panel, entry.name);
        }
    }

    public DefaultListModel<ProviderConfigEntry> getProviderListModel() {
        return providerListModel;
    }

    public JList<ProviderConfigEntry> getProviderList() {
        return providerList;
    }
}
