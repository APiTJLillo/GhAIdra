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
    private final LLMAnalysisManager analysisManager;

    public AnalysisOptionsPanel(LLMAnalysisManager analysisManager) {
        this.analysisManager = analysisManager;
        
        setLayout(new BoxLayout(this, BoxLayout.Y_AXIS));
        setBorder(BorderFactory.createTitledBorder("Analysis Options"));

        // Create checkboxes
        recursiveAnalysisBox = new JCheckBox("Enable Recursive Analysis");
        recursiveRenamingBox = new JCheckBox("Enable Recursive Renaming");
        renameSimilarBox = new JCheckBox("Automatically Rename Similar Functions");

        // Setup listeners
        setupListeners();

        // Layout components
        layoutComponents();
    }

    private void setupListeners() {
        recursiveAnalysisBox.addActionListener(e -> {
            analysisManager.setConfig(new AnalysisConfig());
            analysisManager.getConfig().setRecursiveAnalysis(recursiveAnalysisBox.isSelected());
        });
        
        recursiveRenamingBox.addActionListener(e -> {
            if (analysisManager.getConfig() == null) {
                analysisManager.setConfig(new AnalysisConfig());
            }
            analysisManager.getConfig().setRecursiveRenaming(recursiveRenamingBox.isSelected());
        });

        renameSimilarBox.addActionListener(e -> {
            if (analysisManager.getConfig() == null) {
                analysisManager.setConfig(new AnalysisConfig());
            }
            analysisManager.getConfig().setRenameSimilarFunctions(renameSimilarBox.isSelected());
        });
    }

    private void layoutComponents() {
        // Align checkboxes to the left
        recursiveAnalysisBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        recursiveRenamingBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        renameSimilarBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        // Add components with spacing
        add(recursiveAnalysisBox);
        add(Box.createVerticalStrut(5));
        add(recursiveRenamingBox);
        add(Box.createVerticalStrut(5));
        add(renameSimilarBox);
    }

    public void setEnabled(boolean enabled) {
        recursiveAnalysisBox.setEnabled(enabled);
        recursiveRenamingBox.setEnabled(enabled);
        renameSimilarBox.setEnabled(enabled);
    }

    public void saveState() {
        if (analysisManager.getConfig() == null) {
            analysisManager.setConfig(new AnalysisConfig());
        }
        AnalysisConfig config = analysisManager.getConfig();
        config.setRecursiveAnalysis(recursiveAnalysisBox.isSelected());
        config.setRecursiveRenaming(recursiveRenamingBox.isSelected());
        config.setRenameSimilarFunctions(renameSimilarBox.isSelected());
    }

    public void loadState() {
        if (analysisManager.getConfig() != null) {
            AnalysisConfig config = analysisManager.getConfig();
            recursiveAnalysisBox.setSelected(config.isRecursiveAnalysis());
            recursiveRenamingBox.setSelected(config.isRecursiveRenaming());
            renameSimilarBox.setSelected(config.isRenameSimilarFunctions());
        }
    }
}
