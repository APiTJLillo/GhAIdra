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
    private final JButton simulateButton;
    private final JButton configureButton;
    private final JButton clearButton;
    private final JButton stopButton;
    private volatile boolean operationInProgress;
    private final JPanel analysisButtons;
    private final JPanel simulationButtons;

    public OperationButtonPanel() {
        super(new BorderLayout(5, 5));
        setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        operationButtons = new ArrayList<>();
        operationInProgress = false;
        
        // Initialize buttons
        stopButton = createButton("Stop Operation");
        stopButton.setEnabled(false);
        analyzeButton = createButton("Analyze Function");
        analyzeAllButton = createButton("Analyze All Functions");
        renameFunctionButton = createButton("Rename Function");
        renameAllButton = createButton("Rename Function & Variables");
        simulateButton = createButton("Simulate Function");
        configureButton = createButton("Configure LLM");
        clearButton = createButton("Clear Output");
        
        // Create button panels
        analysisButtons = createButtonRow(analyzeButton, analyzeAllButton, renameFunctionButton, renameAllButton);
        simulationButtons = createButtonRow(simulateButton);
        
        // Layout components
        layoutComponents();

        // Initially hide simulation buttons
        simulationButtons.setVisible(false);
    }

    private JButton createButton(String text) {
        JButton button = new JButton(text);
        operationButtons.add(button);
        return button;
    }

    private void layoutComponents() {
        JPanel contentPanel = new JPanel();
        contentPanel.setLayout(new BoxLayout(contentPanel, BoxLayout.Y_AXIS));
        
        // Create main button panel with some padding
        contentPanel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        // Add button panels with consistent sizing
        contentPanel.add(analysisButtons);
        contentPanel.add(Box.createVerticalStrut(5));
        contentPanel.add(simulationButtons);
        contentPanel.add(Box.createVerticalStrut(5));

        // Add separator before utility buttons
        contentPanel.add(new JSeparator());
        contentPanel.add(Box.createVerticalStrut(5));

        // Add utility buttons
        JPanel utilityButtons = createButtonRow(stopButton, configureButton, clearButton);
        contentPanel.add(utilityButtons);

        // Set preferred button size for consistency
        Dimension buttonSize = new Dimension(150, 25);
        for (JButton button : operationButtons) {
            button.setPreferredSize(buttonSize);
            button.setMinimumSize(buttonSize);
        }
        
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

    public void setSimulateActionListener(Runnable action) {
        simulateButton.addActionListener(e -> {
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

    public synchronized void startOperation() {
        operationInProgress = true;
        SwingUtilities.invokeLater(() -> {
            for (JButton button : operationButtons) {
                if (button != clearButton && button != configureButton && button != stopButton) {
                    button.setEnabled(false);
                }
            }
            stopButton.setEnabled(true);
        });
    }

    public synchronized void finishOperation() {
        operationInProgress = false;
        SwingUtilities.invokeLater(() -> {
            for (JButton button : operationButtons) {
                if (button == stopButton) {
                    button.setEnabled(false);
                } else {
                    button.setEnabled(true);
                }
            }
        });
    }

    public void showAnalysisButtons() {
        analysisButtons.setVisible(true);
        simulationButtons.setVisible(false);
        revalidate();
        repaint();
    }

    public void showSimulationButtons() {
        analysisButtons.setVisible(false);
        simulationButtons.setVisible(true);
        revalidate();
        repaint();
    }

    public void setStopActionListener(Runnable action) {
        stopButton.addActionListener(e -> action.run());
    }

    public boolean isOperationInProgress() {
        return operationInProgress;
    }
}
