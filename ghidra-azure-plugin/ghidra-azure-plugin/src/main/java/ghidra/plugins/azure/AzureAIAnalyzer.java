/* ###
 * IP: Apache License 2.0
 */
package ghidra.plugins.azure;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.CodeViewerService;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "Azure AI Plugin",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Azure OpenAI Function Analyzer",
    description = "Uses Azure OpenAI to analyze and document functions"
)
//@formatter:on
public class AzureAIAnalyzer extends ProgramPlugin {
    private ConsoleService console;
    private AzureAIClient aiClient;
    private FunctionAnalyzer functionAnalyzer;

    public AzureAIAnalyzer(PluginTool tool) {
        super(tool);
        console = tool.getService(ConsoleService.class);
        aiClient = new AzureAIClient(console);
        createActions();
    }

    @Override
    protected void init() {
        // Plugin initialization
    }

    private void createActions() {
        DockingAction analyzeCurrentAction = new DockingAction("Analyze Current Function", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                analyzeCurrentFunction();
            }
        };
        analyzeCurrentAction.setMenuBarData(new MenuData(
            new String[] { "Analysis", "Azure AI", "Analyze Current Function" }));
        tool.addAction(analyzeCurrentAction);

        DockingAction analyzeAllAction = new DockingAction("Analyze All Functions", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                analyzeAllFunctions();
            }
        };
        analyzeAllAction.setMenuBarData(new MenuData(
            new String[] { "Analysis", "Azure AI", "Analyze All Functions" }));
        tool.addAction(analyzeAllAction);
    }

    private void initializeClient() {
        try {
            aiClient.initialize();
        } catch (Exception e) {
            Msg.showError(this, tool.getToolFrame(), "Azure OpenAI Error", e.getMessage());
        }
    }

    private void analyzeCurrentFunction() {
        if (currentProgram == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "No program is open");
            return;
        }

        initializeClient();
        initializeFunctionAnalyzer();

        CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
        if (codeViewer == null || codeViewer.getCurrentLocation() == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "Cannot determine current location");
            return;
        }
        Address currentAddr = codeViewer.getCurrentLocation().getAddress();
        Function currentFunction = currentProgram.getFunctionManager().getFunctionContaining(currentAddr);
        
        if (currentFunction != null) {
            try {
                String analysis = functionAnalyzer.analyzeSingleFunction(currentFunction, TaskMonitor.DUMMY);
                
                if (analysis != null && !analysis.startsWith("AI Analysis Error:")) {
                    // Start transaction for comment update
                    int transaction = currentProgram.startTransaction("Add AI Analysis Comment");
                    boolean success = false;
                    
                    try {
                        // Add the analysis as both a repeatable and EOL comment
                        currentFunction.setRepeatableComment(analysis);
                        currentFunction.setComment(currentFunction.getComment() + "\n" + analysis);
                        
                        console.println("Successfully added analysis for " + currentFunction.getName());
                        success = true;
                    }
                    finally {
                        currentProgram.endTransaction(transaction, success);
                    }
                }
            } catch (Exception e) {
                Msg.showError(this, tool.getToolFrame(), "Analysis Error", e.getMessage());
            }
        } else {
            Msg.showInfo(this, tool.getToolFrame(), "No Function Found", 
                "Please position the cursor within a function to analyze");
        }
    }

    private void analyzeAllFunctions() {
        if (currentProgram == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "No program is open");
            return;
        }

        initializeClient();
        initializeFunctionAnalyzer();

        Task task = new Task("Analyzing Functions", true, false, true) {
            @Override
            public void run(TaskMonitor monitor) throws CancelledException {
                FunctionManager functionManager = currentProgram.getFunctionManager();
                int totalFunctions = getFunctionCount();
                int analyzed = 0;

                monitor.initialize(totalFunctions);
                monitor.setMessage("Analyzing functions with Azure AI...");

                for (Function function : functionManager.getFunctions(true)) {
                    if (monitor.isCancelled()) {
                        break;
                    }

                    try {
                        String analysis = functionAnalyzer.analyzeSingleFunction(function, monitor);
                        if (analysis != null && !analysis.startsWith("AI Analysis Error:")) {
                            // Start transaction for comment update
                            int transaction = currentProgram.startTransaction("Add AI Analysis Comment");
                            boolean success = false;
                            
                            try {
                                // Add the analysis as both a repeatable and EOL comment
                                function.setRepeatableComment(analysis);
                                function.setComment(function.getComment() + "\n" + analysis);
                                success = true;
                            }
                            finally {
                                currentProgram.endTransaction(transaction, success);
                            }
                        }
                        analyzed++;
                        monitor.incrementProgress(1);
                        monitor.setMessage(String.format("Analyzed %d/%d functions", analyzed, totalFunctions));
                    } catch (Exception e) {
                        console.println("Error analyzing function " + function.getName() + ": " + e.getMessage());
                    }
                }

                console.println("Analysis complete. Analyzed " + analyzed + " functions.");
            }
        };

        tool.execute(task);
    }

    private void initializeFunctionAnalyzer() {
        if (functionAnalyzer == null) {
            functionAnalyzer = new FunctionAnalyzer(currentProgram, console, aiClient);
        }
    }

    private int getFunctionCount() {
        int count = 0;
        FunctionManager functionManager = currentProgram.getFunctionManager();
        for (Function function : functionManager.getFunctions(true)) {
            count++;
        }
        return count;
    }

    @Override
    protected void dispose() {
        try {
            if (functionAnalyzer != null) {
                functionAnalyzer.dispose();
                functionAnalyzer = null;
            }
            if (aiClient != null) {
                aiClient.dispose();
                aiClient = null;
            }
        } finally {
            super.dispose();
        }
    }
}
