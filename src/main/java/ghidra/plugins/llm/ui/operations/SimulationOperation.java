package ghidra.plugins.llm.ui.operations;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.plugins.llm.PCODESimulator;
import ghidra.plugins.llm.PCODESimulator.SimulationResult;
import ghidra.plugins.llm.ui.components.SimulationConfigPanel;
import ghidra.plugins.llm.AIInputSuggester;
import ghidra.plugins.llm.LLMProvider;
import ghidra.util.task.TaskMonitor;
import ghidra.app.decompiler.DecompInterface;
import javax.swing.*;
import java.util.Map;
import java.awt.*;
import ghidra.util.Msg;

/**
 * Operation handler for PCODE simulation.
 */
public class SimulationOperation {
    private final Program program;
    private final PCODESimulator simulator;
    private final AIInputSuggester inputSuggester;
    private final SimulationConfigPanel configPanel;
    private final JDialog dialog;
    private Function currentFunction;
    
    public SimulationOperation(Program program, LLMProvider llmProvider) {
        this.program = program;
        this.simulator = new PCODESimulator(program);
        
        // Initialize AI input suggester with decompiler
        DecompInterface decompiler = new DecompInterface();
        decompiler.openProgram(program);
        this.inputSuggester = new AIInputSuggester(llmProvider, decompiler);
        
        // Create config panel
        this.configPanel = new SimulationConfigPanel(new SimulationConfigPanel.ConfigChangeListener() {
            @Override
            public void onConfigurationChanged(Map<String, Object> newConfig) {
                // Config changes are stored in the panel until simulation is run
            }
            
            @Override
            public void onInputsChanged(Map<String, Long> inputs) {
                // Input changes are stored in the panel until simulation is run
            }
            
            @Override
            public void onSuggestInputs(Function function) {
                suggestInputs(function);
            }
        }, inputSuggester);
        
        // Create dialog
        dialog = new JDialog();
        dialog.setTitle("Function Simulation");
        dialog.setLayout(new BorderLayout());
        
        // Add config panel
        dialog.add(configPanel, BorderLayout.CENTER);
        
        // Add buttons
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton runButton = new JButton("Run Simulation");
        JButton closeButton = new JButton("Close");
        
        runButton.addActionListener(e -> runSimulation());
        closeButton.addActionListener(e -> dialog.setVisible(false));
        
        buttonPanel.add(runButton);
        buttonPanel.add(closeButton);
        dialog.add(buttonPanel, BorderLayout.SOUTH);
        
        dialog.setSize(800, 600);
        dialog.setLocationRelativeTo(null);
    }
    
    /**
     * Show the simulation dialog for a function.
     */
    public void showDialog(Function function) {
        this.currentFunction = function;
        dialog.setTitle("Function Simulation - " + function.getName());
        configPanel.setFunction(function);
        dialog.setVisible(true);
    }
    
    /**
     * Generate input suggestions using AI.
     */
    private void suggestInputs(Function function) {
        SwingWorker<Map<String, Long>, Void> worker = new SwingWorker<>() {
            @Override
            protected Map<String, Long> doInBackground() throws Exception {
                return inputSuggester.suggestInputs(function);
            }
            
            @Override
            protected void done() {
                try {
                    Map<String, Long> suggestions = get();
                    configPanel.setSuggestedInputs(suggestions);
                } catch (Exception e) {
                    Msg.error(this, "Failed to generate input suggestions: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    /**
     * Run the simulation with current configuration.
     */
    private void runSimulation() {
        if (currentFunction == null) {
            return;
        }
        
        // Get current configuration
        Map<String, Object> config = configPanel.getConfiguration();
        Map<String, Long> inputs = configPanel.getInputValues();
        
        // Clear previous results
        configPanel.clearResults();
        
        // Run simulation in background
        SwingWorker<SimulationResult, Void> worker = new SwingWorker<>() {
            @Override
            protected SimulationResult doInBackground() throws Exception {
                // Create simulation config from panel settings
                PCODESimulator.SimulationConfig simConfig = new PCODESimulator.SimulationConfig(
                    (Integer)config.get("maxInstructions"),
                    (Boolean)config.get("traceMode"),
                    (Boolean)config.get("captureRegisters"),
                    (Boolean)config.get("captureMemory"),
                    (Integer)config.get("memoryCaptureSize")
                );
                
                return simulator.simulate(currentFunction, inputs, simConfig);
            }
            
            @Override
            protected void done() {
                try {
                    SimulationResult result = get();
                    configPanel.showResults(result);
                    
                    // If simulation had errors, suggest refined inputs
                    if (result.hasErrors()) {
                        Map<String, Long> refinedInputs = inputSuggester.refineInputs(
                            currentFunction, result, inputs);
                        configPanel.setSuggestedInputs(refinedInputs);
                    }
                } catch (Exception e) {
                    Msg.error(this, "Simulation failed: " + e.getMessage());
                }
            }
        };
        worker.execute();
    }
    
    public void dispose() {
        if (simulator != null) {
            simulator.dispose();
        }
        dialog.dispose();
    }
}
