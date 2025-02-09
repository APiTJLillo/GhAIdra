package ghidra.plugins.llm.ui.operations;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.plugins.llm.PCODESimulator;
import ghidra.plugins.llm.PCODESimulator.SimulationResult;
import ghidra.util.task.TaskMonitor;
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
    
    public SimulationOperation(Program program) {
        this.program = program;
        this.simulator = new PCODESimulator(program);
    }
    
    public void executeSimulation(Function function, Map<String, Object> config) {
        // Create results dialog
        JDialog resultsDialog = new JDialog();
        resultsDialog.setTitle("Simulation Results - " + function.getName());
        resultsDialog.setLayout(new BorderLayout());
        resultsDialog.setSize(800, 600);
        resultsDialog.setLocationRelativeTo(null);
        
        // Create results display components
        JTextArea traceOutput = new JTextArea();
        traceOutput.setEditable(false);
        traceOutput.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        JScrollPane scrollPane = new JScrollPane(traceOutput);
        resultsDialog.add(scrollPane, BorderLayout.CENTER);
        
        // Add status panel at bottom
        JPanel statusPanel = new JPanel(new BorderLayout());
        JLabel statusLabel = new JLabel("Running simulation...");
        statusPanel.add(statusLabel, BorderLayout.WEST);
        resultsDialog.add(statusPanel, BorderLayout.SOUTH);
        
        // Show dialog
        resultsDialog.setVisible(true);
        
        // Run simulation in background
        SwingWorker<SimulationResult, Void> worker = new SwingWorker<>() {
            @Override
            protected SimulationResult doInBackground() throws Exception {
                // Convert configuration to simulator inputs
                Map<String, Long> inputs = generateInputs(function);
                return simulator.simulate(function, inputs);
            }
            
            @Override
            protected void done() {
                try {
                    SimulationResult result = get();
                    displayResults(result, traceOutput);
                    statusLabel.setText("Simulation complete");
                } catch (Exception e) {
                    Msg.error(this, "Simulation failed: " + e.getMessage());
                    statusLabel.setText("Simulation failed: " + e.getMessage());
                }
            }
        };
        
        worker.execute();
    }
    
    private Map<String, Long> generateInputs(Function function) {
        // TODO: Use LLM to suggest appropriate input values based on function analysis
        return Map.of(); // For now return empty map
    }
    
    private void displayResults(SimulationResult result, JTextArea output) {
        StringBuilder sb = new StringBuilder();
        
        // Display any errors
        if (result.hasErrors()) {
            sb.append("=== ERRORS ===\n");
            for (String error : result.getErrors()) {
                sb.append(error).append("\n");
            }
            sb.append("\n");
        }
        
        // Display execution trace
        sb.append("=== EXECUTION TRACE ===\n");
        for (PCODESimulator.TraceEntry entry : result.getExecutionTrace()) {
            sb.append(String.format("%s: %s\n", entry.getAddress(), entry.getInstruction()));
            if (!entry.getRegisterState().isEmpty()) {
                sb.append("  Registers:\n");
                entry.getRegisterState().forEach((reg, value) -> 
                    sb.append(String.format("    %s = 0x%x\n", reg, value)));
            }
            sb.append("\n");
        }
        
        // Display return value if any
        if (result.getReturnValue() != null) {
            sb.append(String.format("\nReturn Value: 0x%x\n", result.getReturnValue()));
        }
        
        // Display output parameters
        if (!result.getOutputParameters().isEmpty()) {
            sb.append("\n=== OUTPUT PARAMETERS ===\n");
            result.getOutputParameters().forEach((name, value) -> {
                sb.append(name).append(":\n");
                sb.append("  Raw bytes: ");
                for (byte b : value) {
                    sb.append(String.format("%02x ", b));
                }
                sb.append("\n");
            });
        }
        
        output.setText(sb.toString());
        output.setCaretPosition(0);
    }
    
    public void dispose() {
        if (simulator != null) {
            simulator.dispose();
        }
    }
}
