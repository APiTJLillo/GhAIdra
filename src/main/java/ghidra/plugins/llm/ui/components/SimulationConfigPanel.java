package ghidra.plugins.llm.ui.components;

import javax.swing.*;
import java.awt.*;
import ghidra.framework.plugintool.Plugin;
import java.util.Map;
import java.util.HashMap;
import ghidra.plugins.llm.ui.AbstractPluginComponent;
import ghidra.program.model.listing.Function;
import ghidra.plugins.llm.PCODESimulator.SimulationResult;
import ghidra.plugins.llm.AIInputSuggester;

/**
 * Configuration panel for PCODE simulation settings and function parameters.
 */
public class SimulationConfigPanel extends JPanel {
    private final JSpinner maxInstructionsSpinner;
    private final JCheckBox traceModeCheckbox;
    private final JCheckBox captureRegistersCheckbox;
    private final JCheckBox captureMemoryCheckbox;
    private final JSpinner memoryCaptureSize;
    private final ConfigChangeListener listener;
    private final ParameterInputPanel parameterPanel;
    private final SimulationResultsPanel resultsPanel;
    private AIInputSuggester inputSuggester;

    public interface ConfigChangeListener {
        void onConfigurationChanged(Map<String, Object> newConfig);
        void onInputsChanged(Map<String, Long> inputs);
        void onSuggestInputs(Function function);
    }

    public SimulationConfigPanel(ConfigChangeListener listener, AIInputSuggester inputSuggester) {
        this.listener = listener;
        this.inputSuggester = inputSuggester;
        
        setLayout(new BorderLayout());
        
        // Create parameter and results panels
        parameterPanel = new ParameterInputPanel(new ParameterInputPanel.SuggestionListener() {
            @Override
            public void onSuggestInputs(Function function) {
                if (listener != null) {
                    listener.onSuggestInputs(function);
                }
            }
            
            @Override
            public void onInputsChanged(Map<String, Long> inputs) {
                if (listener != null) {
                    listener.onInputsChanged(inputs);
                }
            }
        });
        
        resultsPanel = new SimulationResultsPanel();
        
        // Split pane for parameters and results
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, parameterPanel, resultsPanel);
        splitPane.setResizeWeight(0.4); // Give 40% to parameter panel
        
        // Create configuration panel
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Max Instructions Configuration
        gbc.gridx = 0;
        gbc.gridy = 0;
        mainPanel.add(new JLabel("Maximum Instructions:"), gbc);
        
        gbc.gridx = 1;
        SpinnerNumberModel maxInstructionsModel = new SpinnerNumberModel(10000, 100, 1000000, 1000);
        maxInstructionsSpinner = new JSpinner(maxInstructionsModel);
        mainPanel.add(maxInstructionsSpinner, gbc);
        
        // Trace Mode Option
        gbc.gridx = 0;
        gbc.gridy++;
        traceModeCheckbox = new JCheckBox("Enable Execution Trace", true);
        mainPanel.add(traceModeCheckbox, gbc);
        
        // Register Capture Option
        gbc.gridy++;
        captureRegistersCheckbox = new JCheckBox("Capture Register States", true);
        mainPanel.add(captureRegistersCheckbox, gbc);
        
        // Memory Capture Option
        gbc.gridy++;
        captureMemoryCheckbox = new JCheckBox("Capture Memory States", true);
        mainPanel.add(captureMemoryCheckbox, gbc);
        
        // Memory Capture Size
        gbc.gridx = 0;
        gbc.gridy++;
        mainPanel.add(new JLabel("Memory Capture Size (bytes):"), gbc);
        
        gbc.gridx = 1;
        SpinnerNumberModel memorySizeModel = new SpinnerNumberModel(16, 1, 1024, 16);
        memoryCaptureSize = new JSpinner(memorySizeModel);
        mainPanel.add(memoryCaptureSize, gbc);
        
        // Create top panel with config options
        JPanel topPanel = new JPanel(new BorderLayout());
        topPanel.add(mainPanel, BorderLayout.NORTH);
        
        // Add all components to main layout
        JPanel contentPanel = new JPanel(new BorderLayout());
        contentPanel.add(topPanel, BorderLayout.NORTH);
        contentPanel.add(splitPane, BorderLayout.CENTER);
        add(contentPanel, BorderLayout.CENTER);
        
        // Add change listeners
        maxInstructionsSpinner.addChangeListener(e -> notifyConfigChanged());
        traceModeCheckbox.addActionListener(e -> notifyConfigChanged());
        captureRegistersCheckbox.addActionListener(e -> notifyConfigChanged());
        captureMemoryCheckbox.addActionListener(e -> notifyConfigChanged());
        memoryCaptureSize.addChangeListener(e -> notifyConfigChanged());
    }

    private void notifyConfigChanged() {
        if (listener != null) {
            listener.onConfigurationChanged(getConfiguration());
        }
    }

    public Map<String, Object> getConfiguration() {
        Map<String, Object> config = new HashMap<>();
        config.put("maxInstructions", maxInstructionsSpinner.getValue());
        config.put("traceMode", traceModeCheckbox.isSelected());
        config.put("captureRegisters", captureRegistersCheckbox.isSelected());
        config.put("captureMemory", captureMemoryCheckbox.isSelected());
        config.put("memoryCaptureSize", memoryCaptureSize.getValue());
        return config;
    }

    public void setConfiguration(Map<String, Object> config) {
        if (config.containsKey("maxInstructions")) {
            maxInstructionsSpinner.setValue(config.get("maxInstructions"));
        }
        if (config.containsKey("traceMode")) {
            traceModeCheckbox.setSelected((Boolean) config.get("traceMode"));
        }
        if (config.containsKey("captureRegisters")) {
            captureRegistersCheckbox.setSelected((Boolean) config.get("captureRegisters"));
        }
        if (config.containsKey("captureMemory")) {
            captureMemoryCheckbox.setSelected((Boolean) config.get("captureMemory"));
        }
        if (config.containsKey("memoryCaptureSize")) {
            memoryCaptureSize.setValue(config.get("memoryCaptureSize"));
        }
    }

    /**
     * Update the current function being analyzed.
     */
    public void setFunction(Function function) {
        parameterPanel.setFunction(function);
        resultsPanel.clearResults();
    }

    /**
     * Update suggested input values.
     */
    public void setSuggestedInputs(Map<String, Long> suggestions) {
        parameterPanel.setSuggestedInputs(suggestions);
    }

    /**
     * Get current parameter input values.
     */
    public Map<String, Long> getInputValues() {
        return parameterPanel.getInputValues();
    }

    /**
     * Display simulation results.
     */
    public void showResults(SimulationResult result) {
        resultsPanel.showResults(result);
    }

    /**
     * Clear all results.
     */
    public void clearResults() {
        resultsPanel.clearResults();
    }
}
