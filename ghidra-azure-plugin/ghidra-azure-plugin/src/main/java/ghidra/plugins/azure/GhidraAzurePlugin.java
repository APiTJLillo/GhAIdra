package ghidra.plugins.azure;

import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;

import com.azure.ai.openai.OpenAIClient;
import com.azure.core.http.HttpClient;
import com.azure.core.http.netty.NettyAsyncHttpClientBuilder;
import com.azure.ai.openai.OpenAIClientBuilder;
import com.azure.ai.openai.models.Completions;
import com.azure.ai.openai.models.CompletionsOptions;
import com.azure.core.credential.AzureKeyCredential;
import docking.ActionContext;
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.ConsoleService;
import ghidra.app.services.CodeViewerService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompiledFunction;

/**
 * Plugin that uses Azure OpenAI to analyze and document functions.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = "ghidra.plugins.azure",
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Azure AI Function Analysis",
    description = "Uses Azure OpenAI to analyze and improve functions",
    servicesRequired = { CodeViewerService.class }
)
public class GhidraAzurePlugin extends ProgramPlugin {

    private OpenAIClient client;
    private static final String MODEL_ID = "deepseek-r1";  // Deepseek model deployment name
    private ConsoleService console;
    private String azureOpenaiKey;
    private String endpoint;
    private DecompInterface decompiler;
    private AzurePluginProvider provider;

    public GhidraAzurePlugin(PluginTool tool) {
        super(tool);
    }

    private DecompInterface getDecompiler() {
        if (decompiler == null) {
            decompiler = new DecompInterface();
            decompiler.openProgram(currentProgram);
        }
        return decompiler;
    }

    // Plugin lifecycle methods
    @Override
    public void init() {
        super.init();
        console = tool.getService(ConsoleService.class);
        
        // Only create and add provider if it doesn't exist
        if (provider == null) {
            provider = new AzurePluginProvider(this, getName());
            tool.addComponentProvider(provider, false);
            provider.setVisible(true);
        }
    }

    @Override
    public void serviceAdded(Class<?> interfaceClass, Object service) {
        super.serviceAdded(interfaceClass, service);
        if (interfaceClass == ConsoleService.class) {
            console = (ConsoleService) service;
        }
    }

    @Override
    public void serviceRemoved(Class<?> interfaceClass, Object service) {
        super.serviceRemoved(interfaceClass, service);
        if (interfaceClass == ConsoleService.class) {
            console = null;
        }
    }

    @Override
    protected void programActivated(Program program) {
        super.programActivated(program);
        if (decompiler != null) {
            decompiler.openProgram(program);
        }
        // Only set provider visible if it exists and isn't already visible
        if (provider != null && !provider.isVisible()) {
            provider.setVisible(true);
        }
    }

    private void loadConfig() {
        try {
            var configStream = getClass().getResourceAsStream("/azure_config.properties");
            if (configStream == null) {
                Msg.showError(this, tool.getToolFrame(), "Azure OpenAI Error", "Could not find azure_config.properties");
                return;
            }

            var props = new java.util.Properties();
            props.load(configStream);

            azureOpenaiKey = props.getProperty("azure.openai.key");
            endpoint = props.getProperty("azure.openai.endpoint");

            if (azureOpenaiKey == null || endpoint == null) {
                Msg.showError(this, tool.getToolFrame(), "Azure OpenAI Error", 
                    "Missing required properties in azure_config.properties");
                return;
            }
        } catch (Exception e) {
            Msg.showError(this, tool.getToolFrame(), "Azure OpenAI Error", 
                "Error loading configuration: " + e.getMessage());
        }
    }

    private synchronized void initializeClient() throws Exception {
        if (client != null) {
            return;
        }

        loadConfig();
        if (azureOpenaiKey == null || endpoint == null) {
            throw new Exception("Azure OpenAI configuration is missing or incomplete");
        }

        try {
            // Configure SSL for development
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            // Set the default SSL context
            SSLContext.setDefault(sslContext);
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

            // Configure SSL properties
            System.setProperty("jdk.tls.client.protocols", "TLSv1.2");
            System.setProperty("https.protocols", "TLSv1.2");
            System.setProperty("com.azure.http.enable-system-truststore", "false");

            // Create HTTP client configuration with SSL context
            HttpClient httpClient = new NettyAsyncHttpClientBuilder()
                .port(443)  // HTTPS port
                .wiretap(true)  // Enable debug logging
                .build();

            // Build client with custom HTTP client
            client = new OpenAIClientBuilder()
                .endpoint(endpoint)
                .credential(new AzureKeyCredential(azureOpenaiKey))
                .httpClient(httpClient)
                .buildClient();

            console.println("Successfully connected to Azure OpenAI");
        } catch (Exception e) {
            String errorMessage = "Azure OpenAI Error: " + e.getMessage();
            if (e instanceof SSLException || e.getCause() instanceof SSLException) {
                errorMessage += "\nSSL Error: Please check your SSL/TLS configuration.";
            }
            Msg.showError(this, tool.getToolFrame(), "Azure OpenAI Error", errorMessage);
            throw e;
        }
    }

    public void analyzeCurrentFunction() {
        if (currentProgram == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "No program is open");
            return;
        }

        CodeViewerService codeViewer = tool.getService(CodeViewerService.class);
        if (codeViewer == null || codeViewer.getCurrentLocation() == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "Cannot determine current location");
            return;
        }
        Address currentAddr = codeViewer.getCurrentLocation().getAddress();
        Function currentFunction = currentProgram.getFunctionManager().getFunctionContaining(currentAddr);
        
        if (currentFunction == null) {
            Msg.showInfo(this, tool.getToolFrame(), "No Function Found", 
                "Please position the cursor within a function to analyze");
            return;
        }

        // Create and execute task
        tool.execute(new Task("Analyzing Current Function", true, false, true) {
            @Override
            public void run(TaskMonitor monitor) throws CancelledException {
                try {
                    initializeClient();
                    analyzeSingleFunction(currentFunction, monitor);
                } catch (Exception e) {
                    Msg.showError(GhidraAzurePlugin.this, tool.getToolFrame(), "Analysis Error", e.getMessage());
                }
            }
        });
    }

    private void analyzeSingleFunction(Function function, TaskMonitor monitor) throws Exception {
        if (monitor.isCancelled()) {
            return;
        }

        console.println("\nAnalyzing function: " + function.getName());
        monitor.setMessage("Analyzing function: " + function.getName());

        try {
            // Get function details with progress monitoring
            monitor.setMessage("Getting function details...");
            String functionDetails = getFunctionDetails(function);
            
            // Check for cancellation
            if (monitor.isCancelled()) {
                return;
            }

            // Analyze with AI
            monitor.setMessage("Sending to Azure OpenAI for analysis...");
            String functionAnalysis = analyzeWithAI(functionDetails);

            // Check for analysis errors
            if (functionAnalysis.startsWith("AI Analysis Error:")) {
                throw new Exception(functionAnalysis);
            }

            // Start transaction for comment update
            int transaction = currentProgram.startTransaction("Add AI Analysis Comment");
            boolean success = false;
            
            try {
                // Add the analysis as both a repeatable and EOL comment
                function.setRepeatableComment(functionAnalysis);
                function.setComment(function.getComment() + "\n" + functionAnalysis);
                
                console.println("Successfully added analysis for " + function.getName());
                success = true;
            }
            catch (Exception e) {
                console.println("Error setting comment for " + function.getName() + ": " + e.getMessage());
                throw e;
            }
            finally {
                currentProgram.endTransaction(transaction, success);
            }
        }
        catch (Exception e) {
            console.println("Error analyzing " + function.getName() + ": " + e.getMessage());
            throw e;
        }
    }

    private void analyzeAllFunctions() {
        if (currentProgram == null) {
            Msg.showError(this, tool.getToolFrame(), "Error", "No program is open");
            return;
        }

        try {
            initializeClient();
        } catch (Exception e) {
            Msg.showError(this, tool.getToolFrame(), "Error", "Failed to initialize Azure OpenAI client: " + e.getMessage());
            return;
        }

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
                        analyzeSingleFunction(function, monitor);
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

    public String getFunctionDetails(Function function) {
        StringBuilder details = new StringBuilder();
        try {
            // Basic function information
            details.append("=== Function Information ===\n");
            details.append("Function Name: ").append(function.getName()).append("\n");
            details.append("Entry Point: ").append(function.getEntryPoint()).append("\n");
            details.append("Signature: ").append(function.getSignature()).append("\n");
            details.append("Return Type: ").append(function.getReturnType()).append("\n");
            
            // Get existing comments if any
            String existingComment = function.getComment();
            if (existingComment != null && !existingComment.trim().isEmpty()) {
                details.append("\n=== Existing Comments ===\n");
                details.append(existingComment).append("\n");
            }
            
            // Add information about references to this function
            details.append("\n=== References To This Function ===\n");
            currentProgram.getReferenceManager()
                .getReferencesTo(function.getEntryPoint())
                .forEach(ref -> {
                    if (ref.getReferenceType().isCall()) {
                        details.append("Called from: ").append(ref.getFromAddress()).append("\n");
                    }
                });
            
            // Decompiled code
            details.append("\n=== Decompiled Code ===\n");
            DecompInterface decomp = getDecompiler();
            if (decomp != null && currentProgram != null) {
                DecompiledFunction decompiled = decomp.decompileFunction(function, 30, TaskMonitor.DUMMY).getDecompiledFunction();
                if (decompiled != null) {
                    details.append(decompiled.getC());
                }
            }
            
            return details.toString();
        } catch (Exception e) {
            console.println("Error getting details for " + function.getName() + ": " + e.getMessage());
            return "Error getting function details: " + e.getMessage();
        } finally {
            if (decompiler != null) {
                decompiler.closeProgram();
            }
        }
    }

    public String analyzeWithAI(String code) {
        try {
            if (client == null) {
                initializeClient();
            }

            List<String> prompt = new ArrayList<>();
            
            prompt.add("You are an expert reverse engineer and software analyst. Your task is to analyze decompiled code " +
                "and provide clear, detailed insights. Focus on security implications, algorithmic patterns, and " +
                "potential improvements. Be precise and technical in your explanations.\n\n" +
                "Analyze this decompiled code considering:\n" +
                "1. Function purpose and behavior\n" +
                "2. Key algorithms or data structures used\n" +
                "3. Notable code patterns or common functions called\n" +
                "4. Potential security implications\n" +
                "5. Suggestions for variable/function renaming if unclear\n\n" +
                "Code:\n```\n" + code + "\n```");

            CompletionsOptions options = new CompletionsOptions(prompt);
            options.setMaxTokens(2000);  // Increased for more detailed analysis
            options.setTemperature(0.1); // Very low for factual responses

            console.println("Sending analysis request to Azure OpenAI...");
            Completions completions = client.getCompletions(MODEL_ID, options);
            String analysis = completions.getChoices().get(0).getText().trim();
            
            console.println("\nAnalysis received. Processing results...");
            return "=== Function Analysis ===\n\n" + analysis;
        } catch (Exception e) {
            console.println("Error during AI analysis: " + e.getMessage());
            return "AI Analysis Error: " + e.getMessage();
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
        super.dispose();
        if (client != null) {
            client = null;
        }
        if (decompiler != null) {
            decompiler.dispose();
            decompiler = null;
        }
        if (provider != null) {
            provider.setVisible(false);  // Hide provider before removal
            try {
                tool.removeComponentProvider(provider);
            } catch (Exception e) {
                // Ignore any errors during disposal
            }
            provider = null;
        }
    }


    @Override
    protected void programDeactivated(Program program) {
        if (provider != null) {
            provider.setVisible(false);
        }
    }
}
