package ghidra.plugins.llm.ui.components;

import javax.swing.*;
import java.awt.*;
import java.util.Properties;
import ghidra.plugins.llm.AnalysisConfig;
import ghidra.plugins.llm.LLMAnalysisManager;
import ghidra.plugins.llm.config.ConfigManager;

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

    private final ConfigManager configManager;

    public AnalysisOptionsPanel(LLMAnalysisManager analysisManager) {
        this.analysisManager = analysisManager;
        this.configManager = ConfigManager.getInstance();
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createTitledBorder("Analysis Options"));

        // Create checkboxes with saved states
        Properties savedOptions = configManager.getAnalysisOptions();
        recursiveAnalysisBox = new JCheckBox("Enable Recursive Analysis", 
            Boolean.parseBoolean(savedOptions.getProperty("analysis.recursive", "false")));
        recursiveRenamingBox = new JCheckBox("Enable Recursive Renaming",
            Boolean.parseBoolean(savedOptions.getProperty("analysis.recursive.renaming", "false")));
        renameSimilarBox = new JCheckBox("Automatically Rename Similar Functions",
            Boolean.parseBoolean(savedOptions.getProperty("analysis.rename.similar", "false")));
        ignoreRenamedBox = new JCheckBox("Only Rename FUN_ Functions",
            Boolean.parseBoolean(savedOptions.getProperty("analysis.ignore.renamed", "false")));
        
        // Create recursion depth spinner with saved state
        int savedDepth = Integer.parseInt(savedOptions.getProperty("analysis.recursion.depth", "0"));
        SpinnerNumberModel spinnerModel = new SpinnerNumberModel(savedDepth, 0, 100, 1);
        recursionDepthSpinner = new JSpinner(spinnerModel);
        recursionDepthSpinner.setEnabled(recursiveAnalysisBox.isSelected() || recursiveRenamingBox.isSelected());
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
            updateConfig();
            saveOptions();
            updateRecursionSpinner();
        });
        
        recursiveRenamingBox.addActionListener(e -> {
            updateConfig();
            saveOptions();
            updateRecursionSpinner();
        });

        renameSimilarBox.addActionListener(e -> {
            updateConfig();
            saveOptions();
        });

        ignoreRenamedBox.addActionListener(e -> {
            updateConfig();
            saveOptions();
        });

        recursionDepthSpinner.addChangeListener(e -> {
            updateConfig();
            saveOptions();
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

    public void updateConfig() {
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

    public void saveOptions() {
        Properties options = new Properties();
        options.setProperty("analysis.recursive", String.valueOf(recursiveAnalysisBox.isSelected()));
        options.setProperty("analysis.recursive.renaming", String.valueOf(recursiveRenamingBox.isSelected()));
        options.setProperty("analysis.rename.similar", String.valueOf(renameSimilarBox.isSelected()));
        options.setProperty("analysis.ignore.renamed", String.valueOf(ignoreRenamedBox.isSelected()));
        options.setProperty("analysis.recursion.depth", String.valueOf(recursionDepthSpinner.getValue()));
        configManager.saveAnalysisOptions(options);
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
