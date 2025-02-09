package ghidra.plugins.llm.ui;

import javax.swing.*;
import java.awt.*;

import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.providers.openai.OpenAIConfig;

public class OpenAIConfigPanel extends ProviderConfigPanel {
    private JTextField apiKeyField;
    private JTextField modelField;
    private JTextField temperatureField;
    private JTextField maxTokensField;

    public OpenAIConfigPanel() {
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
        nameField.setText("OpenAI");
        modelField.setText("gpt-4-turbo-preview");
        temperatureField.setText("0.7");
        maxTokensField.setText("2048");
    }

    @Override
    public LLMConfig getConfig() {
        OpenAIConfig config = new OpenAIConfig();
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
        if (!(config instanceof OpenAIConfig)) {
            throw new IllegalArgumentException("Expected OpenAIConfig");
        }

        OpenAIConfig openAIConfig = (OpenAIConfig) config;
        nameField.setText(openAIConfig.getDisplayName());
        apiKeyField.setText(openAIConfig.getApiKey());
        modelField.setText(openAIConfig.getModel());
        temperatureField.setText(String.valueOf(openAIConfig.getTemperature()));
        maxTokensField.setText(String.valueOf(openAIConfig.getMaxTokens()));
        enabledCheckbox.setSelected(openAIConfig.isEnabled());
    }

    @Override
    public String getProviderType() {
        return "openai";
    }
}
