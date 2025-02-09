package ghidra.plugins.llm.ui.components;

import javax.swing.*;
import java.awt.*;
import javax.swing.table.DefaultTableModel;
import ghidra.plugins.llm.PCODESimulator.SimulationResult;
import ghidra.plugins.llm.PCODESimulator.TraceEntry;
import java.util.Map;

/**
 * Panel for displaying simulation results including execution trace and register states.
 */
public class SimulationResultsPanel extends JPanel {
    private final JTextArea errorArea;
    private final JTable traceTable;
    private final DefaultTableModel traceModel;
    private final JTable registerTable;
    private final DefaultTableModel registerModel;
    private final JTextField returnValueField;
    private final JTextArea outputArea;

    public SimulationResultsPanel() {
        setLayout(new BorderLayout());
        
        // Create tabbed pane for different result views
        JTabbedPane tabbedPane = new JTabbedPane();
        
        // Execution Trace Panel
        JPanel tracePanel = new JPanel(new BorderLayout());
        String[] traceColumns = {"Address", "Instruction", "Details"};
        traceModel = new DefaultTableModel(traceColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        traceTable = new JTable(traceModel);
        tracePanel.add(new JScrollPane(traceTable), BorderLayout.CENTER);
        tabbedPane.addTab("Execution Trace", tracePanel);
        
        // Register States Panel
        JPanel registerPanel = new JPanel(new BorderLayout());
        String[] registerColumns = {"Register", "Value"};
        registerModel = new DefaultTableModel(registerColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        registerTable = new JTable(registerModel);
        registerPanel.add(new JScrollPane(registerTable), BorderLayout.CENTER);
        tabbedPane.addTab("Register States", registerPanel);
        
        // Results Summary Panel
        JPanel summaryPanel = new JPanel(new BorderLayout());
        JPanel topPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        
        // Return Value
        gbc.gridx = 0;
        gbc.gridy = 0;
        topPanel.add(new JLabel("Return Value:"), gbc);
        
        gbc.gridx = 1;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        returnValueField = new JTextField();
        returnValueField.setEditable(false);
        topPanel.add(returnValueField, gbc);
        
        // Output Parameters
        gbc.gridx = 0;
        gbc.gridy = 1;
        gbc.gridwidth = 2;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weighty = 1.0;
        outputArea = new JTextArea();
        outputArea.setEditable(false);
        summaryPanel.add(topPanel, BorderLayout.NORTH);
        summaryPanel.add(new JScrollPane(outputArea), BorderLayout.CENTER);
        tabbedPane.addTab("Results Summary", summaryPanel);
        
        // Error Panel
        errorArea = new JTextArea();
        errorArea.setEditable(false);
        errorArea.setForeground(Color.RED);
        JPanel errorPanel = new JPanel(new BorderLayout());
        errorPanel.add(new JScrollPane(errorArea), BorderLayout.CENTER);
        tabbedPane.addTab("Errors", errorPanel);
        
        add(tabbedPane, BorderLayout.CENTER);
    }

    /**
     * Display simulation results.
     */
    public void showResults(SimulationResult result) {
        // Clear previous results
        traceModel.setRowCount(0);
        registerModel.setRowCount(0);
        errorArea.setText("");
        returnValueField.setText("");
        outputArea.setText("");
        
        if (result == null) {
            return;
        }
        
        // Show execution trace
        for (TraceEntry entry : result.getExecutionTrace()) {
            traceModel.addRow(new Object[]{
                entry.getAddress().toString(),
                entry.getInstruction(),
                formatRegisterState(entry.getRegisterState())
            });
        }
        
        // Show final register state if available
        if (!result.getExecutionTrace().isEmpty()) {
            TraceEntry lastEntry = result.getExecutionTrace().get(result.getExecutionTrace().size() - 1);
            for (Map.Entry<String, Long> reg : lastEntry.getRegisterState().entrySet()) {
                registerModel.addRow(new Object[]{
                    reg.getKey(),
                    String.format("0x%X", reg.getValue())
                });
            }
        }
        
        // Show return value
        if (result.getReturnValue() != null) {
            returnValueField.setText(String.format("0x%X", result.getReturnValue()));
        }
        
        // Show output parameters
        StringBuilder output = new StringBuilder();
        output.append("Output Parameters:\n\n");
        for (Map.Entry<String, byte[]> param : result.getOutputParameters().entrySet()) {
            output.append(param.getKey()).append(":\n");
            byte[] value = param.getValue();
            for (int i = 0; i < value.length; i += 16) {
                output.append(String.format("%04X: ", i));
                for (int j = 0; j < 16 && i + j < value.length; j++) {
                    output.append(String.format("%02X ", value[i + j]));
                }
                output.append("\n");
            }
            output.append("\n");
        }
        outputArea.setText(output.toString());
        
        // Show errors if any
        if (result.hasErrors()) {
            StringBuilder errors = new StringBuilder();
            for (String error : result.getErrors()) {
                errors.append(error).append("\n");
            }
            errorArea.setText(errors.toString());
        }
    }

    private String formatRegisterState(Map<String, Long> state) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, Long> entry : state.entrySet()) {
            if (sb.length() > 0) {
                sb.append(", ");
            }
            sb.append(String.format("%s=0x%X", entry.getKey(), entry.getValue()));
        }
        return sb.toString();
    }

    /**
     * Clear all results.
     */
    public void clearResults() {
        showResults(null);
    }
}
