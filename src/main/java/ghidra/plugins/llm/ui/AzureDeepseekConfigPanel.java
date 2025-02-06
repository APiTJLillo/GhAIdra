package ghidra.plugins.llm.ui;

import javax.swing.*;
import java.awt.*;
import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.providers.azure.AzureDeepseekConfig;

public class AzureDeepseekConfigPanel extends ProviderConfigPanel {
    private JTextField endpointField;
    private JTextField keyField;
    private JTextField deploymentField;
    private JSpinner temperatureSpinner;
    private JSpinner maxTokensSpinner;

    public AzureDeepseekConfigPanel() {
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
        deploymentField = new JTextField(40);

        endpointField.setToolTipText("Enter the base URL up to your deployment name, e.g.: https://your-resource.openai.azure.com/openai/deployments/your-deployment");
        addLabeledField("Base URL:", endpointField, gbc);
        addLabeledField("API Key:", keyField, gbc);
        addLabeledField("Deployment Name:", deploymentField, gbc);

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
        AzureDeepseekConfig config = new AzureDeepseekConfig(
            endpointField.getText().trim(),
            keyField.getText().trim(),
            deploymentField.getText().trim(),
            getProviderName()
        );
        config.setTemperature((Double) temperatureSpinner.getValue());
        config.setMaxTokens((Integer) maxTokensSpinner.getValue());
        return config;
    }

    @Override
    public void loadConfig(LLMConfig config) {
        if (!(config instanceof AzureDeepseekConfig)) {
            throw new IllegalArgumentException("Expected AzureDeepseekConfig");
        }
        AzureDeepseekConfig deepseekConfig = (AzureDeepseekConfig) config;
        
        nameField.setText(deepseekConfig.getDisplayName());
        endpointField.setText(deepseekConfig.getEndpoint());
        keyField.setText(deepseekConfig.getKey());
        deploymentField.setText(deepseekConfig.getModelForAnalysis());
        temperatureSpinner.setValue(deepseekConfig.getTemperature());
        maxTokensSpinner.setValue(deepseekConfig.getMaxTokens());
    }

    @Override
    public String getProviderType() {
        return "azure-deepseek";
    }
}
