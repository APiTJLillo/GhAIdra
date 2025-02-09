package ghidra.plugins.llm.ui.config;

import javax.swing.*;
import java.awt.*;
import java.util.function.Consumer;

/**
 * Tab panel for managing general LLM configuration settings.
 */
public class GeneralSettingsTab extends JPanel {
    private final JComboBox<String> analysisProviderCombo;
    private final JComboBox<String> renamingProviderCombo;
    private final Consumer<Void> onConfigChanged;

    public GeneralSettingsTab(Consumer<Void> onConfigChanged) {
        this.onConfigChanged = onConfigChanged;
        setLayout(new GridBagLayout());
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Default Analysis Provider
        gbc.gridx = 0;
        gbc.gridy = 0;
        add(new JLabel("Default Analysis Provider:"), gbc);
        gbc.gridx = 1;
        analysisProviderCombo = new JComboBox<>();
        analysisProviderCombo.addActionListener(e -> onConfigChanged.accept(null));
        add(analysisProviderCombo, gbc);

        // Default Renaming Provider
        gbc.gridx = 0;
        gbc.gridy++;
        add(new JLabel("Default Renaming Provider:"), gbc);
        gbc.gridx = 1;
        renamingProviderCombo = new JComboBox<>();
        renamingProviderCombo.addActionListener(e -> onConfigChanged.accept(null));
        add(renamingProviderCombo, gbc);
    }

    public void updateProviders(DefaultListModel<ProviderConfigEntry> providerListModel) {
        analysisProviderCombo.removeAllItems();
        renamingProviderCombo.removeAllItems();

        for (int i = 0; i < providerListModel.getSize(); i++) {
            ProviderConfigEntry entry = providerListModel.getElementAt(i);
            String displayName = entry.config.getDisplayName();
            analysisProviderCombo.addItem(displayName);
            renamingProviderCombo.addItem(displayName);
        }
    }

    public void setDefaultAnalysisProvider(String provider) {
        analysisProviderCombo.setSelectedItem(provider);
    }

    public void setDefaultRenamingProvider(String provider) {
        renamingProviderCombo.setSelectedItem(provider);
    }

    public String getSelectedAnalysisProvider() {
        return (String) analysisProviderCombo.getSelectedItem();
    }

    public String getSelectedRenamingProvider() {
        return (String) renamingProviderCombo.getSelectedItem();
    }
}
