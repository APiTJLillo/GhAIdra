package ghidra.plugins.llm.ui;

import javax.swing.*;
import java.awt.*;

import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.providers.anthropic.AnthropicConfig;

public class AnthropicConfigPanel extends ProviderConfigPanel {
    private JTextField apiKeyField;
    private JTextField modelField;
    private JTextField temperatureField;
    private JTextField maxTokensField;

    public AnthropicConfigPanel() {
        super();
        initializeComponents();
    }

    private void initializeComponents() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);

        // API Key
        gbc.gridy = 2;
        apiKeyField = new JPasswordField(40);
        addLabeledField("API Key:", apiKeyField, gbc);

        // Model
        gbc.gridy = 3;
        modelField = new JTextField(40);
        addLabeledField("Model:", modelField, gbc);

        // Temperature
        gbc.gridy = 4;
        temperatureField = new JTextField(10);
        addLabeledField("Temperature:", temperatureField, gbc);

        // Max Tokens
        gbc.gridy = 5;
        maxTokensField = new JTextField(10);
        addLabeledField("Max Tokens:", maxTokensField, gbc);

        // Set default values
        setProviderName("Anthropic");
        modelField.setText("claude-3-opus-20240229");
        temperatureField.setText("0.7");
        maxTokensField.setText("2048");
    }

    @Override
    public LLMConfig getConfig() {
        AnthropicConfig config = new AnthropicConfig();
        config.setDisplayName(getProviderName());
        config.setApiKey(apiKeyField.getText());
        config.setModel(modelField.getText());
        config.setEnabled(isEnabled());

        try {
            config.setTemperature(Double.parseDouble(temperatureField.getText()));
        } catch (NumberFormatException e) {
            config.setTemperature(0.7); // Default if invalid
        }

        try {
            config.setMaxTokens(Integer.parseInt(maxTokensField.getText()));
        } catch (NumberFormatException e) {
            config.setMaxTokens(2048); // Default if invalid
        }

        return config;
    }

    @Override
    public void loadConfig(LLMConfig config) {
        if (!(config instanceof AnthropicConfig)) {
            throw new IllegalArgumentException("Expected AnthropicConfig");
        }

        AnthropicConfig anthropicConfig = (AnthropicConfig) config;
        setProviderName(anthropicConfig.getDisplayName());
        apiKeyField.setText(anthropicConfig.getApiKey());
        modelField.setText(anthropicConfig.getModel());
        temperatureField.setText(String.valueOf(anthropicConfig.getTemperature()));
        maxTokensField.setText(String.valueOf(anthropicConfig.getMaxTokens()));
        setEnabled(anthropicConfig.isEnabled());
    }

    @Override
    public String getProviderType() {
        return "anthropic";
    }
}
