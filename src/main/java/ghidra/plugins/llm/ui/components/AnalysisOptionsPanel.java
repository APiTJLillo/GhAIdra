package ghidra.plugins.llm.ui.components;

import javax.swing.*;
import java.awt.*;
import ghidra.plugins.llm.AnalysisConfig;
import ghidra.plugins.llm.LLMAnalysisManager;

/**
 * Panel containing analysis configuration options.
 */
public class AnalysisOptionsPanel extends JPanel {
    private final JCheckBox recursiveAnalysisBox;
    private final JCheckBox recursiveRenamingBox;
    private final JCheckBox renameSimilarBox;
    private final JCheckBox ignoreRenamedBox;
    private final JSpinner recursionDepthSpinner;
    private final LLMAnalysisManager analysisManager;

    public AnalysisOptionsPanel(LLMAnalysisManager analysisManager) {
        this.analysisManager = analysisManager;
        
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createTitledBorder("Analysis Options"));

        // Create checkboxes
        recursiveAnalysisBox = new JCheckBox("Enable Recursive Analysis");
        recursiveRenamingBox = new JCheckBox("Enable Recursive Renaming");
        renameSimilarBox = new JCheckBox("Automatically Rename Similar Functions");
        ignoreRenamedBox = new JCheckBox("Only Rename FUN_ Functions");
        
        // Create recursion depth spinner
        SpinnerNumberModel spinnerModel = new SpinnerNumberModel(0, 0, 100, 1);
        recursionDepthSpinner = new JSpinner(spinnerModel);
        recursionDepthSpinner.setEnabled(false); // Initially disabled
        JComponent editor = recursionDepthSpinner.getEditor();
        if (editor instanceof JSpinner.DefaultEditor) {
            JTextField tf = ((JSpinner.DefaultEditor) editor).getTextField();
            tf.setColumns(3); // Make spinner input field narrower
        }

        // Setup listeners
        setupListeners();

        // Layout components
        layoutComponents();
    }

    private void updateRecursionSpinner() {
        boolean enabled = recursiveAnalysisBox.isSelected() || recursiveRenamingBox.isSelected();
        recursionDepthSpinner.setEnabled(enabled);
    }

    private void setupListeners() {
        recursiveAnalysisBox.addActionListener(e -> {
            analysisManager.setConfig(new AnalysisConfig());
            analysisManager.getConfig().setRecursiveAnalysis(recursiveAnalysisBox.isSelected());
            updateRecursionSpinner();
        });
        
        recursiveRenamingBox.addActionListener(e -> {
            if (analysisManager.getConfig() == null) {
                analysisManager.setConfig(new AnalysisConfig());
            }
            analysisManager.getConfig().setRecursiveRenaming(recursiveRenamingBox.isSelected());
            updateRecursionSpinner();
        });

        renameSimilarBox.addActionListener(e -> {
            if (analysisManager.getConfig() == null) {
                analysisManager.setConfig(new AnalysisConfig());
            }
            analysisManager.getConfig().setRenameSimilarFunctions(renameSimilarBox.isSelected());
        });

        ignoreRenamedBox.addActionListener(e -> {
            if (analysisManager.getConfig() == null) {
                analysisManager.setConfig(new AnalysisConfig());
            }
            analysisManager.getConfig().setIgnoreRenamed(ignoreRenamedBox.isSelected());
        });

        recursionDepthSpinner.addChangeListener(e -> {
            if (analysisManager.getConfig() == null) {
                analysisManager.setConfig(new AnalysisConfig());
            }
            analysisManager.getConfig().setRecursionDepth((Integer) recursionDepthSpinner.getValue());
        });
    }

    private void layoutComponents() {
        // Create panel for recursion depth with label
        JPanel depthPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        depthPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        JLabel depthLabel = new JLabel("Recursion Depth (0 = infinite):");
        depthPanel.add(depthLabel);
        depthPanel.add(recursionDepthSpinner);

        // Align components to the left
        recursiveAnalysisBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        recursiveRenamingBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        renameSimilarBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        ignoreRenamedBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        // Add components with spacing
        add(recursiveAnalysisBox);
        add(Box.createVerticalStrut(5));
        add(recursiveRenamingBox);
        add(Box.createVerticalStrut(5));
        add(depthPanel);
        add(Box.createVerticalStrut(10));
        add(renameSimilarBox);
        add(Box.createVerticalStrut(5));
        add(ignoreRenamedBox);
    }

    public void setEnabled(boolean enabled) {
        recursiveAnalysisBox.setEnabled(enabled);
        recursiveRenamingBox.setEnabled(enabled);
        renameSimilarBox.setEnabled(enabled);
        ignoreRenamedBox.setEnabled(enabled);
        recursionDepthSpinner.setEnabled(enabled && 
            (recursiveAnalysisBox.isSelected() || recursiveRenamingBox.isSelected()));
    }

    public void saveState() {
        if (analysisManager.getConfig() == null) {
            analysisManager.setConfig(new AnalysisConfig());
        }
        AnalysisConfig config = analysisManager.getConfig();
        config.setRecursiveAnalysis(recursiveAnalysisBox.isSelected());
        config.setRecursiveRenaming(recursiveRenamingBox.isSelected());
        config.setRenameSimilarFunctions(renameSimilarBox.isSelected());
        config.setIgnoreRenamed(ignoreRenamedBox.isSelected());
        config.setRecursionDepth((Integer) recursionDepthSpinner.getValue());
    }

    public void loadState() {
        if (analysisManager.getConfig() != null) {
            AnalysisConfig config = analysisManager.getConfig();
            recursiveAnalysisBox.setSelected(config.isRecursiveAnalysis());
            recursiveRenamingBox.setSelected(config.isRecursiveRenaming());
            renameSimilarBox.setSelected(config.isRenameSimilarFunctions());
            ignoreRenamedBox.setSelected(config.isIgnoreRenamed());
            recursionDepthSpinner.setValue(config.getRecursionDepth());
            updateRecursionSpinner();
        }
    }
}
