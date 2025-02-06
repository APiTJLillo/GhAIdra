/* ###
 * IP: Apache License 2.0
 */
package ghidra.plugins.azure;

import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.azure.ai.openai.OpenAIClient;
import com.azure.ai.openai.OpenAIClientBuilder;
import com.azure.ai.openai.models.*;
import com.azure.core.credential.AzureKeyCredential;
import ghidra.app.services.ConsoleService;
import java.util.List;

/**
 * Wrapper for Azure OpenAI client to handle API interactions
 */
public class AzureAIClient {
    private OpenAIClient client;
    private final ConsoleService console;
    private static final String DEPLOYMENT_NAME = "gpt-35-turbo";
    private String azureOpenaiKey;
    private String endpoint;

    public AzureAIClient(ConsoleService console) {
        this.console = console;
    }

    public void initialize() throws Exception {
        if (client != null) {
            return;
        }

        // Configure system-wide SSL to trust all certificates (for testing only)
        configureSSL();

        // Get API credentials
        if (!setCredentials()) {
            throw new Exception("Failed to set Azure OpenAI credentials");
        }

        // Configure the Azure OpenAI client
        client = new OpenAIClientBuilder()
            .endpoint(endpoint)
            .credential(new AzureKeyCredential(azureOpenaiKey))
            .buildClient();

        console.println("SSL Provider: " + SSLContext.getDefault().getProvider().getName());
        console.println("Successfully connected to Azure OpenAI");
    }

    private void configureSSL() {
        try {
            // Force JDK SSL provider and debug mode
            System.setProperty("io.netty.handler.ssl.noOpenSsl", "true");
            System.setProperty("javax.net.debug", "ssl:handshake");
            System.setProperty("jdk.tls.client.protocols", "TLSv1.2");

            // Print system information for debugging
            console.println("Java Version: " + System.getProperty("java.version"));
            console.println("Java Home: " + System.getProperty("java.home"));
        } catch (Exception e) {
            console.println("Warning: Failed to configure SSL: " + e.getMessage());
        }
    }

    private boolean setCredentials() {
        azureOpenaiKey = System.getenv("AZURE_OPENAI_KEY");
        endpoint = System.getenv("AZURE_OPENAI_ENDPOINT");
        
        return azureOpenaiKey != null && endpoint != null;
    }

    public String analyze(String prompt) throws Exception {
        CompletionsOptions options = new CompletionsOptions(List.of(prompt))
            .setMaxTokens(1000)
            .setTemperature(0.3);

        console.println("Sending analysis request to Azure OpenAI...");
        
        Completions completions = client.getCompletions(DEPLOYMENT_NAME, options);
        String analysis = completions.getChoices().get(0).getText();
        
        console.println("\nAnalysis received. Processing results...");
        return analysis;
    }

    public void dispose() {
        client = null;
    }
}
