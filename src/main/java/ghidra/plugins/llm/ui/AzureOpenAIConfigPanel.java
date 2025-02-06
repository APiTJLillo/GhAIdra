package ghidra.plugins.llm.ui;

import javax.swing.*;
import java.awt.*;
import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.providers.azure.AzureConfig;

public class AzureOpenAIConfigPanel extends ProviderConfigPanel {
    private JTextField endpointField;
    private JTextField keyField;
    private JTextField modelField;
    private JSpinner temperatureSpinner;
    private JSpinner maxTokensSpinner;

    public AzureOpenAIConfigPanel() {
        super();
        initializeComponents();
    }

    private void initializeComponents() {
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridwidth = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.gridy = 2; // Start after common components

        endpointField = new JTextField(40);
        keyField = new JTextField(40);
        modelField = new JTextField(40);

        endpointField.setToolTipText("Enter the complete Azure OpenAI endpoint URL including your deployment name, e.g.: https://your-resource.openai.azure.com/openai/deployments/deployment-name");
        addLabeledField("Endpoint URL:", endpointField, gbc);
        addLabeledField("API Key:", keyField, gbc);
        addLabeledField("Model:", modelField, gbc);

        // Temperature spinner
        SpinnerNumberModel tempModel = new SpinnerNumberModel(0.7, 0.0, 2.0, 0.1);
        temperatureSpinner = new JSpinner(tempModel);
        addLabeledField("Temperature:", temperatureSpinner, gbc);

        // Max tokens spinner
        SpinnerNumberModel tokenModel = new SpinnerNumberModel(2000, 100, 16000, 100);
        maxTokensSpinner = new JSpinner(tokenModel);
        addLabeledField("Max Tokens:", maxTokensSpinner, gbc);
    }

    @Override
    public LLMConfig getConfig() {
        AzureConfig config = new AzureConfig(
            endpointField.getText().trim(),
            keyField.getText().trim(),
            modelField.getText().trim(),
            getProviderName()
        );
        return config;
    }

    @Override
    public void loadConfig(LLMConfig config) {
        if (!(config instanceof AzureConfig)) {
            throw new IllegalArgumentException("Expected AzureConfig");
        }
        AzureConfig azureConfig = (AzureConfig) config;
        
        nameField.setText(azureConfig.getDisplayName());
        endpointField.setText(azureConfig.getEndpoint());
        keyField.setText(azureConfig.getKey());
        modelField.setText(azureConfig.getModelForAnalysis());
        temperatureSpinner.setValue(azureConfig.getTemperature());
        maxTokensSpinner.setValue(azureConfig.getMaxTokens());
    }

    @Override
    public String getProviderType() {
        return "azure-openai";
    }
}
