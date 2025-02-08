package ghidra.plugins.llm.ui.components;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Panel containing operation buttons with state management and action handling.
 */
public class OperationButtonPanel extends JPanel {
    private final List<JButton> operationButtons;
    private final JButton analyzeButton;
    private final JButton analyzeAllButton;
    private final JButton renameFunctionButton;
    private final JButton renameAllButton;
    private final JButton configureButton;
    private final JButton clearButton;
    private volatile boolean operationInProgress;

    public OperationButtonPanel() {
        super(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        operationButtons = new ArrayList<>();
        operationInProgress = false;
        
        // Initialize buttons
        analyzeButton = createButton("Analyze Function");
        analyzeAllButton = createButton("Analyze All Functions");
        renameFunctionButton = createButton("Rename Function");
        renameAllButton = createButton("Rename Function & Variables");
        configureButton = createButton("Configure LLM");
        clearButton = createButton("Clear Output");
        
        // Layout components
        layoutComponents();
    }

    private JButton createButton(String text) {
        JButton button = new JButton(text);
        operationButtons.add(button);
        return button;
    }

    private void layoutComponents() {
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        
        // Function Analysis Section
        JPanel analysisButtons = createButtonRow(analyzeButton, analyzeAllButton);
        
        // Renaming Section
        JPanel renameButtons = createButtonRow(renameFunctionButton, renameAllButton);

        // Utility Buttons Section
        JPanel utilityButtons = createButtonRow(configureButton, clearButton);

        // Add all sections
        contentPanel.add(analysisButtons);
        contentPanel.add(Box.createVerticalStrut(5));
        contentPanel.add(renameButtons);
        contentPanel.add(Box.createVerticalStrut(5));
        contentPanel.add(utilityButtons);
        
        add(contentPanel, BorderLayout.CENTER);
    }

    private JPanel createButtonRow(JButton... buttons) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 5));
        for (JButton button : buttons) {
            panel.add(button);
        }
        return panel;
    }

    public void setAnalyzeActionListener(Runnable action) {
        analyzeButton.addActionListener(e -> {
            if (!operationInProgress) {
                startOperation();
                try {
                    action.run();
                } catch (Exception ex) {
                    finishOperation();
                }
            }
        });
    }

    public void setAnalyzeAllActionListener(Runnable action) {
        analyzeAllButton.addActionListener(e -> {
            if (!operationInProgress) {
                startOperation();
                try {
                    action.run();
                } catch (Exception ex) {
                    finishOperation();
                }
            }
        });
    }

    public void setRenameFunctionActionListener(Runnable action) {
        renameFunctionButton.addActionListener(e -> {
            if (!operationInProgress) {
                startOperation();
                try {
                    action.run();
                } catch (Exception ex) {
                    finishOperation();
                }
            }
        });
    }

    public void setRenameAllActionListener(Runnable action) {
        renameAllButton.addActionListener(e -> {
            if (!operationInProgress) {
                startOperation();
                try {
                    action.run();
                } catch (Exception ex) {
                    finishOperation();
                }
            }
        });
    }

    public void setConfigureActionListener(Runnable action) {
        configureButton.addActionListener(e -> action.run());
    }

    public void setClearActionListener(Runnable action) {
        clearButton.addActionListener(e -> action.run());
    }

    public synchronized void startOperation() {
        operationInProgress = true;
        SwingUtilities.invokeLater(() -> {
            for (JButton button : operationButtons) {
                if (button != clearButton && button != configureButton) {
                    button.setEnabled(false);
                }
            }
        });
    }

    public synchronized void finishOperation() {
        operationInProgress = false;
        SwingUtilities.invokeLater(() -> {
            for (JButton button : operationButtons) {
                button.setEnabled(true);
            }
        });
    }

    public boolean isOperationInProgress() {
        return operationInProgress;
    }
}
