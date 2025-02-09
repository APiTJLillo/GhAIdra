package ghidra.plugins.llm.ui.components;

import javax.swing.*;
import java.awt.*;
import ghidra.plugins.llm.ui.UpdateListener;
import ghidra.plugins.llm.FunctionSummaryResponse;
import ghidra.util.Msg;

/**
 * Panel containing analysis output and summary text areas.
 */
public class AnalysisOutputPanel extends JPanel {
    private final JTextArea outputArea;
    private final JTextArea summaryArea;
    private final JProgressBar progressBar;
    private UpdateListener updateListener;

    public AnalysisOutputPanel() {
        super(new BorderLayout(10, 10));
        
        // Initialize text areas
        outputArea = createTextArea();
        summaryArea = createTextArea();
        
        // Create progress bar
        progressBar = new JProgressBar(0, 100);
        progressBar.setStringPainted(true);
        progressBar.setVisible(false);
        
        // Create split pane
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        
        // Setup output area
        JScrollPane outputScroll = new JScrollPane(outputArea);
        outputScroll.setBorder(BorderFactory.createTitledBorder("Detailed Analysis"));
        splitPane.setTopComponent(outputScroll);
        
        // Setup summary area
        JScrollPane summaryScroll = new JScrollPane(summaryArea);
        summaryScroll.setBorder(BorderFactory.createTitledBorder("Function Summary"));
        splitPane.setBottomComponent(summaryScroll);
        
        // Configure split pane
        splitPane.setResizeWeight(0.7);
        splitPane.setDividerLocation(0.7);
        
        // Layout with progress bar
        JPanel mainPanel = new JPanel(new BorderLayout(5, 5));
        mainPanel.add(splitPane, BorderLayout.CENTER);
        
        JPanel progressPanel = new JPanel(new BorderLayout());
        progressPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
        progressPanel.add(progressBar, BorderLayout.CENTER);
        mainPanel.add(progressPanel, BorderLayout.SOUTH);
        
        add(mainPanel, BorderLayout.CENTER);
    }

    private JTextArea createTextArea() {
        JTextArea area = new JTextArea();
        area.setEditable(false);
        area.setWrapStyleWord(true);
        area.setLineWrap(true);
        area.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        return area;
    }

    public void setUpdateListener(UpdateListener listener) {
        this.updateListener = listener;
    }

    public void appendOutput(String text) {
        SwingUtilities.invokeLater(() -> {
            outputArea.append(text);
            outputArea.setCaretPosition(outputArea.getDocument().getLength());
        });
    }

    public void setSummary(String text) {
        SwingUtilities.invokeLater(() -> {
            summaryArea.setText(text);
            summaryArea.setCaretPosition(0);
        });
    }

    public void displayAnalysisResult(FunctionSummaryResponse result, String functionName) {
        if (result != null) {
            setSummary(result.getSummary());
            appendOutput("Function Summary: " + result.getSummary() + "\n\n");
            
            FunctionSummaryResponse.Details details = result.getDetails();
            if (details != null) {
                appendOutput("Purpose: " + details.getPurpose() + "\n\n");
                appendOutput("Algorithmic Patterns: " + details.getAlgorithmicPatterns() + "\n\n");
                appendOutput("Security Implications: " + details.getSecurityImplications() + "\n");
            }
            appendOutput("\n----------------------------------------\n");
            appendOutput("Analysis complete for: " + functionName + "\n");
        } else {
            appendOutput("Error: Failed to analyze function\n");
        }
    }

    public void displayError(String errorMessage) {
        appendOutput("\nError: " + errorMessage + "\n");
        Msg.error(this, errorMessage);
    }

    public void clearOutput() {
        SwingUtilities.invokeLater(() -> {
            outputArea.setText("");
            summaryArea.setText("");
            progressBar.setVisible(false);
            if (updateListener != null) {
                updateListener.onUpdate();
            }
        });
    }

    public void startAnalysis(String functionName) {
        clearOutput();
        appendOutput("Analyzing function: " + functionName + "\n");
        appendOutput("This may take a few minutes. You'll see the response stream as it arrives.\n");
        appendOutput("----------------------------------------\n");
    }

    public void startBatchAnalysis(int totalFunctions) {
        clearOutput();
        appendOutput("Starting batch analysis of " + totalFunctions + " functions...\n");
        appendOutput("This may take several minutes. Progress will be shown as functions are processed.\n");
        appendOutput("----------------------------------------\n\n");
        
        SwingUtilities.invokeLater(() -> {
            progressBar.setValue(0);
            progressBar.setString("Starting batch analysis...");
            progressBar.setVisible(true);
            summaryArea.setText(String.format("Processing 0/%d functions", totalFunctions));
        });
    }

    public void updateBatchProgress(int completed, int total) {
        SwingUtilities.invokeLater(() -> {
            int percentage = (int)((completed * 100.0) / total);
            progressBar.setValue(percentage);
            progressBar.setString(String.format("Processing %d/%d functions (%d%%)", 
                completed, total, percentage));
            summaryArea.setText(String.format("Batch Operation Progress\nCompleted: %d/%d functions\nProgress: %.1f%%", 
                completed, total, (completed * 100.0) / total));
        });
    }

    public void startRenaming(String functionName) {
        clearOutput();
        appendOutput("Generating rename suggestions for: " + functionName + "\n");
        appendOutput("----------------------------------------\n");
    }
}
