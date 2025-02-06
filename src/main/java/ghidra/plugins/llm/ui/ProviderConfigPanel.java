package ghidra.plugins.llm.ui;

import javax.swing.*;
import java.awt.*;
import ghidra.plugins.llm.LLMConfig;

public abstract class ProviderConfigPanel extends JPanel {
    protected JTextField nameField;
    protected JCheckBox enabledCheckbox;

    public ProviderConfigPanel() {
        setLayout(new GridBagLayout());
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        initializeCommonComponents();
    }

    private void initializeCommonComponents() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Provider name
        gbc.gridx = 0;
        gbc.gridy = 0;
        add(new JLabel("Provider Name:"), gbc);
        gbc.gridx = 1;
        nameField = new JTextField(40);
        add(nameField, gbc);

        // Enabled checkbox
        gbc.gridx = 0;
        gbc.gridy++;
        enabledCheckbox = new JCheckBox("Enabled");
        enabledCheckbox.setSelected(true);
        add(enabledCheckbox, gbc);
    }

    protected void addLabeledField(String label, JComponent field, GridBagConstraints gbc) {
        gbc.gridx = 0;
        gbc.gridy++;
        add(new JLabel(label), gbc);
        gbc.gridx = 1;
        add(field, gbc);
    }

    public abstract LLMConfig getConfig();
    public abstract void loadConfig(LLMConfig config);
    public abstract String getProviderType();

    public String getProviderName() {
        return nameField.getText().trim();
    }

    public boolean isEnabled() {
        return enabledCheckbox.isSelected();
    }
}
