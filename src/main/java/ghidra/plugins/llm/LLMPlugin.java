package ghidra.plugins.llm;

import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Function;
import ghidra.program.util.ProgramLocation;
import ghidra.program.model.address.Address;
import ghidra.plugins.llm.providers.azure.AzureConfig;
import ghidra.plugins.llm.ui.LLMPluginProvider;
import ghidra.plugins.llm.ui.LLMConfigDialog;
import ghidra.plugins.llm.config.ConfigManager;
import java.util.Properties;
import ghidra.plugins.llm.providers.azure.AzureDeepseekConfig;
import ghidra.plugins.llm.providers.azure.AzureDeepseekProvider;
import ghidra.plugins.llm.providers.azure.AzureOpenAIProvider;
import ghidra.util.task.TaskMonitor;
import ghidra.util.Msg;
import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;

@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = "LLMPlugin",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "LLM-based code analysis",
    description = "Analyzes and suggests improvements for functions using various LLM providers"
)
public class LLMPlugin extends ProgramPlugin {
    private LLMPluginProvider provider;
    private LLMAnalysisManager analysisManager;
    private LLMProviderRegistry registry;

    public LLMPlugin(PluginTool tool) {
        super(tool);
        registry = LLMProviderRegistry.getInstance();
        setupDefaultProviders();
        createActions();
    }

    private void setupDefaultProviders() {
        ConfigManager configManager = ConfigManager.getInstance();
        boolean hasValidProvider = false;
        
        try {
            // Clear existing providers
            for (String type : registry.getProviderTypes()) {
                registry.unregisterProvider(type);
            }

            // Reload Azure OpenAI provider
            Properties openAiProps = configManager.getProviderConfig("azure-openai");
            AzureConfig openAIConfig = new AzureConfig(
                openAiProps.getProperty("endpoint", ""),
                openAiProps.getProperty("key", ""),
                openAiProps.getProperty("analysis.model", ""),
                "azure-openai"
            );
            if (openAIConfig.isValid()) {
                System.out.println("[DEBUG] Loading Azure OpenAI Provider in plugin");
                System.out.println("[DEBUG] - Endpoint: " + openAIConfig.getEndpoint());
                System.out.println("[DEBUG] - Model: " + openAIConfig.getModelForAnalysis());
                registry.registerProvider(new AzureOpenAIProvider(), openAIConfig);
                hasValidProvider = true;
            }

            // Reload Azure Deepseek provider
            Properties deepseekProps = configManager.getProviderConfig("azure-deepseek");
            AzureDeepseekConfig deepseekConfig = new AzureDeepseekConfig(
                deepseekProps.getProperty("endpoint", ""),
                deepseekProps.getProperty("key", ""),
                deepseekProps.getProperty("analysis.model", "deepseek-r1"),
                "azure-deepseek"
            );
            
            if (deepseekConfig.isValid()) {
                System.out.println("[DEBUG] Loading Azure Deepseek Provider in plugin");
                System.out.println("[DEBUG] - Endpoint: " + deepseekConfig.getEndpoint());
                System.out.println("[DEBUG] - Model: " + deepseekConfig.getModelForAnalysis());
                registry.registerProvider(new AzureDeepseekProvider(), deepseekConfig);
                hasValidProvider = true;
            }
        } catch (Exception e) {
            System.out.println("[DEBUG] Error setting up providers: " + e.getMessage());
            e.printStackTrace();
        }

        // Show warning if no valid providers
        if (!hasValidProvider) {
            Msg.showWarn(this, tool.getToolFrame(), "Configuration Warning",
                "No LLM providers have been configured.\n" +
                "Please configure at least one provider in the LLM settings.");
        }
    }

    private void createActions() {
        DockingAction analyzeAction = new DockingAction("Analyze Current Function", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                analyzeCurrentFunction();
            }
        };
        analyzeAction.setMenuBarData(new MenuData(
            new String[] {"Analysis", "LLM Analysis", "Analyze Current Function"}));
        analyzeAction.setEnabled(true);
        tool.addAction(analyzeAction);

        DockingAction renameAction = new DockingAction("Suggest Renames", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                suggestRenames();
            }
        };
        renameAction.setMenuBarData(new MenuData(
            new String[] {"Analysis", "LLM Analysis", "Suggest Renames"}));
        renameAction.setEnabled(true);
        tool.addAction(renameAction);

        DockingAction analyzeAllAction = new DockingAction("Analyze All Functions", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                analyzeAllFunctions();
            }
        };
        analyzeAllAction.setMenuBarData(new MenuData(
            new String[] {"Analysis", "LLM Analysis", "Analyze All Functions"}));
        analyzeAllAction.setEnabled(true);
        tool.addAction(analyzeAllAction);

        DockingAction configureAction = new DockingAction("Configure LLM", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                showConfigDialog();
            }
        };
        configureAction.setMenuBarData(new MenuData(
            new String[] {"Analysis", "LLM Analysis", "Configure..."}));
        configureAction.setEnabled(true);
        tool.addAction(configureAction);
    }

    @Override
    protected void init() {
        super.init();
        if (currentProgram != null) {
            analysisManager = new LLMAnalysisManager(currentProgram);
            provider = new LLMPluginProvider(this, analysisManager);
            provider.addUpdateListener(provider::clearOutput);
            tool.addComponentProvider(provider, true);
        }
    }

    @Override
    protected void programActivated(Program program) {
        if (analysisManager == null) {
            analysisManager = new LLMAnalysisManager(program);
            provider = new LLMPluginProvider(this, analysisManager);
            tool.addComponentProvider(provider, true);
        } else {
            analysisManager.setProgram(program);
        }
    }

    @Override
    protected void programDeactivated(Program program) {
        if (provider != null) {
            provider.clearOutput();
        }
    }

    private void analyzeCurrentFunction() {
        if (currentProgram == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "No program is loaded");
            return;
        }

        ProgramLocation location = currentLocation;
        if (location == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "No location selected");
            return;
        }

        Address address = location.getAddress();
        if (address == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "Invalid address");
            return;
        }

        Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "No function at current location");
            return;
        }

        provider.analyzeFunction(function);
    }

    private void suggestRenames() {
        if (currentProgram == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "No program is loaded");
            return;
        }

        ProgramLocation location = currentLocation;
        if (location == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "No location selected");
            return;
        }

        Address address = location.getAddress();
        if (address == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "Invalid address");
            return;
        }

        Function function = currentProgram.getFunctionManager().getFunctionContaining(address);
        if (function == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "No function at current location");
            return;
        }

        provider.suggestRenamesForFunction(function);
    }

    private void showConfigDialog() {
        LLMConfigDialog dialog = new LLMConfigDialog(tool.getToolFrame(), true, this);
        dialog.setVisible(true);
        // Reload providers after config changes
        setupDefaultProviders();
    }

    private void analyzeAllFunctions() {
        if (currentProgram == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "No program is loaded");
            return;
        }

        provider.clearOutput();
        provider.appendOutput("Analyzing all functions...\n");

        currentProgram.getFunctionManager().getFunctions(true).forEach(function -> {
            if (!provider.isDisposed()) {
                provider.analyzeFunction(function);
            }
        });
    }

    @Override
    protected void dispose() {
        if (provider != null) {
            tool.removeComponentProvider(provider);
            provider = null;
        }
        if (analysisManager != null) {
            analysisManager.dispose();
            analysisManager = null;
        }
        registry.dispose();
        super.dispose();
    }
}
