package ghidra.plugins.llm.ui.components;

import javax.swing.*;
import java.awt.*;
import java.util.HashMap;
import java.util.Map;
import javax.swing.table.DefaultTableModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;

/**
 * Panel for configuring function parameter inputs with AI suggestions.
 */
public class ParameterInputPanel extends JPanel {
    private final JTable parameterTable;
    private final DefaultTableModel tableModel;
    private final JButton suggestButton;
    private final Map<String, JTextField> paramFields;
    private Function currentFunction;
    private SuggestionListener listener;

    public interface SuggestionListener {
        void onSuggestInputs(Function function);
        void onInputsChanged(Map<String, Long> inputs);
    }

    public ParameterInputPanel(SuggestionListener listener) {
        this.listener = listener;
        this.paramFields = new HashMap<>();
        
        setLayout(new BorderLayout());
        setBorder(BorderFactory.createTitledBorder("Function Parameters"));

        // Create table for parameters
        String[] columnNames = {"Parameter", "Type", "Value"};
        tableModel = new DefaultTableModel(columnNames, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return column == 2; // Only value column is editable
            }
        };
        
        parameterTable = new JTable(tableModel);
        parameterTable.getColumnModel().getColumn(2).setCellEditor(
            new DefaultCellEditor(new JTextField())
        );
        
        // Add toolbar with actions
        JPanel toolbarPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        suggestButton = new JButton("Suggest Inputs");
        suggestButton.addActionListener(e -> {
            if (currentFunction != null && listener != null) {
                listener.onSuggestInputs(currentFunction);
            }
        });
        toolbarPanel.add(suggestButton);
        
        add(toolbarPanel, BorderLayout.NORTH);
        add(new JScrollPane(parameterTable), BorderLayout.CENTER);
        
        // Add table listener for value changes
        parameterTable.getModel().addTableModelListener(e -> {
            if (e.getColumn() == 2) { // Value column
                notifyInputsChanged();
            }
        });
    }

    /**
     * Update the panel with a new function's parameters.
     */
    public void setFunction(Function function) {
        this.currentFunction = function;
        tableModel.setRowCount(0);
        paramFields.clear();
        
        if (function != null) {
            for (Parameter param : function.getParameters()) {
                tableModel.addRow(new Object[]{
                    param.getName(),
                    param.getDataType().getName(),
                    ""
                });
            }
        }
        
        suggestButton.setEnabled(function != null);
    }

    /**
     * Update input values with AI suggestions.
     */
    public void setSuggestedInputs(Map<String, Long> suggestions) {
        if (currentFunction != null) {
            int row = 0;
            for (Parameter param : currentFunction.getParameters()) {
                String name = param.getName();
                if (suggestions.containsKey(name)) {
                    tableModel.setValueAt(
                        String.valueOf(suggestions.get(name)),
                        row,
                        2
                    );
                }
                row++;
            }
        }
    }

    /**
     * Get current input values.
     */
    public Map<String, Long> getInputValues() {
        Map<String, Long> values = new HashMap<>();
        
        if (currentFunction != null) {
            int row = 0;
            for (Parameter param : currentFunction.getParameters()) {
                String name = param.getName();
                String valueStr = (String)tableModel.getValueAt(row, 2);
                try {
                    if (!valueStr.isEmpty()) {
                        values.put(name, Long.parseLong(valueStr));
                    }
                } catch (NumberFormatException e) {
                    // Skip invalid values
                }
                row++;
            }
        }
        
        return values;
    }

    private void notifyInputsChanged() {
        if (listener != null) {
            listener.onInputsChanged(getInputValues());
        }
    }
}
