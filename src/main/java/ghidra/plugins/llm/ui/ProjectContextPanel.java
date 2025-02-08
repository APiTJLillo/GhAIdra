package ghidra.plugins.llm.ui;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.Map;
import java.util.List;

import ghidra.plugins.llm.ProjectContext;

public class ProjectContextPanel extends JPanel {
    private JTextField projectNameField;
    private JTextField projectTypeField;
    private JTextArea descriptionArea;
    private DefaultTableModel patternsModel;
    private DefaultTableModel terminologyModel;
    private DefaultTableModel hintsModel;
    private ProjectContext context;

    public ProjectContextPanel() {
        setLayout(new BorderLayout(10, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        initComponents();
    }

    private void initComponents() {
        // Basic Info Panel
        JPanel basicInfoPanel = new JPanel(new GridBagLayout());
        basicInfoPanel.setBorder(BorderFactory.createTitledBorder("Basic Project Information"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.anchor = GridBagConstraints.WEST;
        gbc.insets = new Insets(5, 5, 5, 5);

        // Project Name
        basicInfoPanel.add(new JLabel("Project Name:"), gbc);
        gbc.gridx++;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        projectNameField = new JTextField(20);
        basicInfoPanel.add(projectNameField, gbc);

        // Project Type
        gbc.gridx = 0;
        gbc.gridy++;
        gbc.weightx = 0;
        JLabel typeLabel = new JLabel("Project Type:");
        typeLabel.setToolTipText("e.g., Game Client, Device Driver, Network Service");
        basicInfoPanel.add(typeLabel, gbc);
        gbc.gridx++;
        gbc.weightx = 1.0;
        projectTypeField = new JTextField(20);
        projectTypeField.setToolTipText("The type of application being analyzed");
        basicInfoPanel.add(projectTypeField, gbc);

        // Description field
        gbc.gridx = 0;
        gbc.gridy++;
        gbc.weightx = 0;
        JLabel descLabel = new JLabel("Description:");
        descLabel.setToolTipText("Main description of the application and its key components");
        basicInfoPanel.add(descLabel, gbc);
        gbc.gridx++;
        gbc.weightx = 1.0;
        descriptionArea = new JTextArea(3, 20);
        descriptionArea.setLineWrap(true);
        descriptionArea.setWrapStyleWord(true);
        descriptionArea.setToolTipText("Example:\nUltima Online Stygian Abyss client\n" +
                               "Uses Gamebryo engine\n" +
                               "Uses LuaPlus for scripting\n" +
                               "Lua calls are translated to C++ using events");
        JScrollPane descScroll = new JScrollPane(descriptionArea);
        basicInfoPanel.add(descScroll, gbc);

        // Main Content Panel with Tables
        JPanel tablesPanel = new JPanel(new GridLayout(1, 3, 10, 0));

        // Examples Panel
        JPanel examplesPanel = new JPanel(new BorderLayout());
        examplesPanel.setBorder(BorderFactory.createTitledBorder("Examples"));
        JTextArea examplesArea = new JTextArea(
            """
            Common Patterns example:
            - Lua function calls are wrapped in event handlers
            - Network packets use a standard header format
            - UI elements are created through XML templates
            
            Domain Terminology example:
            Term: LuaPlus
            Description: Extended Lua scripting engine used for game logic
            
            Term: Gamebryo
            Description: 3D game engine providing rendering and physics
            
            Contextual Hints example:
            Category: Network Protocol
            Value: Uses custom packet format with 2-byte headers
            
            Category: Script Integration
            Value: Most Lua functions map to C++ event handlers
            """);
        examplesArea.setEditable(false);
        examplesArea.setBackground(new Color(245, 245, 245));
        JScrollPane examplesScroll = new JScrollPane(examplesArea);
        examplesPanel.add(examplesScroll, BorderLayout.CENTER);
        add(examplesPanel, BorderLayout.EAST);

        // Common Patterns Table
        patternsModel = new DefaultTableModel(new Object[]{"Pattern"}, 0);
        JTable patternsTable = new JTable(patternsModel);
        JPanel patternsPanel = createTablePanel("Common Patterns", patternsTable, 
            new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    patternsModel.addRow(new Object[]{""});
                }
            });

        // Domain Terminology Table
        terminologyModel = new DefaultTableModel(new Object[]{"Term", "Description"}, 0);
        JTable terminologyTable = new JTable(terminologyModel);
        JPanel terminologyPanel = createTablePanel("Domain Terminology", terminologyTable,
            new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    terminologyModel.addRow(new Object[]{"", ""});
                }
            });

        // Contextual Hints Table
        hintsModel = new DefaultTableModel(new Object[]{"Category", "Value"}, 0);
        JTable hintsTable = new JTable(hintsModel);
        JPanel hintsPanel = createTablePanel("Contextual Hints", hintsTable,
            new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    hintsModel.addRow(new Object[]{"", ""});
                }
            });

        tablesPanel.add(patternsPanel);
        tablesPanel.add(terminologyPanel);
        tablesPanel.add(hintsPanel);

        // Layout
        setLayout(new BorderLayout(10, 10));
        add(basicInfoPanel, BorderLayout.NORTH);
        add(tablesPanel, BorderLayout.CENTER);
    }

    private JPanel createTablePanel(String title, final JTable table, ActionListener addAction) {
        JPanel panel = new JPanel(new BorderLayout(5, 5));
        panel.setBorder(BorderFactory.createTitledBorder(title));

        // Scroll pane for table
        JScrollPane scrollPane = new JScrollPane(table);
        panel.add(scrollPane, BorderLayout.CENTER);

        // Button panel
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton addButton = new JButton("Add");
        JButton removeButton = new JButton("Remove");

        addButton.addActionListener(addAction);
        removeButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                DefaultTableModel model = (DefaultTableModel)table.getModel();
                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) {
                    model.removeRow(selectedRow);
                }
            }
        });

        buttonPanel.add(addButton);
        buttonPanel.add(removeButton);
        panel.add(buttonPanel, BorderLayout.SOUTH);

        return panel;
    }

    public void loadContext(ProjectContext context) {
        this.context = context;
        
        // Load basic info
        projectNameField.setText(context.getProjectName());
        projectTypeField.setText(context.getProjectType());
        descriptionArea.setText(context.getDescription());

        // Clear and load patterns
        patternsModel.setRowCount(0);
        for (String pattern : context.getCommonPatterns()) {
            patternsModel.addRow(new Object[]{pattern});
        }

        // Clear and load terminology
        terminologyModel.setRowCount(0);
        for (Map.Entry<String, String> entry : context.getDomainTerminology().entrySet()) {
            terminologyModel.addRow(new Object[]{entry.getKey(), entry.getValue()});
        }

        // Clear and load hints
        hintsModel.setRowCount(0);
        for (Map.Entry<String, String> entry : context.getContextualHints().entrySet()) {
            hintsModel.addRow(new Object[]{entry.getKey(), entry.getValue()});
        }
    }

    public void saveContext() {
        if (context == null) {
            context = new ProjectContext();
        }

        // Save basic info
        context.setProjectName(projectNameField.getText().trim());
        context.setProjectType(projectTypeField.getText().trim());
        context.setDescription(descriptionArea.getText().trim());

        // Save patterns
        for (int i = 0; i < patternsModel.getRowCount(); i++) {
            String pattern = (String)patternsModel.getValueAt(i, 0);
            if (pattern != null && !pattern.trim().isEmpty()) {
                context.addCommonPattern(pattern.trim());
            }
        }

        // Save terminology
        for (int i = 0; i < terminologyModel.getRowCount(); i++) {
            String term = (String)terminologyModel.getValueAt(i, 0);
            String description = (String)terminologyModel.getValueAt(i, 1);
            if (term != null && !term.trim().isEmpty() && description != null) {
                context.setDomainTerm(term.trim(), description.trim());
            }
        }

        // Save hints
        for (int i = 0; i < hintsModel.getRowCount(); i++) {
            String category = (String)hintsModel.getValueAt(i, 0);
            String value = (String)hintsModel.getValueAt(i, 1);
            if (category != null && !category.trim().isEmpty() && value != null) {
                context.setContextualHint(category.trim(), value.trim());
            }
        }
    }

    public ProjectContext getContext() {
        saveContext();
        return context;
    }
}
