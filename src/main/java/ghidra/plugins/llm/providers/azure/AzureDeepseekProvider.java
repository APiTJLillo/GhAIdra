package ghidra.plugins.llm.providers.azure;

import java.io.IOException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ArrayNode;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.MediaType;

import ghidra.plugins.llm.LLMConfig;
import ghidra.plugins.llm.LLMProvider;
import ghidra.util.Msg;

/**
 * Azure OpenAI service provider implementation using direct HTTP requests.
 */
public class AzureDeepseekProvider implements LLMProvider {
    private OkHttpClient client;
    private AzureDeepseekConfig config;
    private final ObjectMapper mapper = new ObjectMapper();
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private static final int TIMEOUT_SECONDS = 120;
    private static final String DEEPSEEK_MODEL = "deepseek-r1";
    private static final String DEEPSEEK_DEPLOYMENT = "deepseek-api";

    @Override
    public void configure(LLMConfig config) {
        if (!(config instanceof AzureDeepseekConfig)) {
            throw new IllegalArgumentException("Expected AzureDeepseekConfig");
        }
        this.config = (AzureDeepseekConfig) config;
        setupClient();
    }

    private void setupClient() {
        if (!config.isValid()) {
            throw new IllegalStateException("Invalid Azure configuration");
        }

        this.client = new OkHttpClient.Builder()
            .connectTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build();
    }

    @Override
    public CompletableFuture<String> analyze(String prompt) {
        return makeChatRequest(prompt, "You are a helpful assistant.", config.getModelForAnalysis());
    }

    @Override
    public CompletableFuture<String> analyzeFunction(String prompt) {
        return makeChatRequest(
            prompt,
            "You are an expert reverse engineer analyzing decompiled code. " +
            "Focus on identifying the purpose, parameters, and behavior of functions.",
            config.getModelForAnalysis()
        );
    }

    public CompletableFuture<String> suggest(String prompt) {
        return makeChatRequest(
            prompt,
            "You are an expert code analyzer focused on suggesting clear, descriptive names for functions and variables.",
            config.getModelForRenaming()
        );
    }

    private CompletableFuture<String> makeChatRequest(String prompt, String systemPrompt, String modelId) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                ObjectNode root = mapper.createObjectNode();
                root.put("model", modelId);
                root.put("temperature", config.getTemperature());
                root.put("max_tokens", config.getMaxTokens());

                ArrayNode messages = root.putArray("messages");
                ObjectNode systemMessage = messages.addObject();
                systemMessage.put("role", "system");
                systemMessage.put("content", systemPrompt);

                ObjectNode userMessage = messages.addObject();
                userMessage.put("role", "user");
                userMessage.put("content", prompt);

                // Clean up the endpoint URL
                String baseEndpoint = config.getEndpoint().replaceAll("/+$", ""); // Remove trailing slashes
                
                // Extract base URL if full URL was provided
                if (baseEndpoint.contains("/chat/completions")) {
                    baseEndpoint = baseEndpoint.substring(0, baseEndpoint.indexOf("/chat/completions"));
                }
                if (baseEndpoint.contains("?api-version=")) {
                    baseEndpoint = baseEndpoint.substring(0, baseEndpoint.indexOf("?api-version="));
                }
                
                // Remove deployment path if it exists
                if (baseEndpoint.endsWith(DEEPSEEK_DEPLOYMENT)) {
                    baseEndpoint = baseEndpoint.substring(0, baseEndpoint.lastIndexOf("/deployments/"));
                }
                
                // Construct deployment path
                String deploymentPath = String.format("/deployments/%s/chat/completions?api-version=2023-05-15", DEEPSEEK_DEPLOYMENT);
                
                // Build final URL
                String requestUrl = baseEndpoint + deploymentPath;
                Msg.debug(this, String.format("Making request to: %s (model: %s)", requestUrl, modelId));
                
                RequestBody body = RequestBody.create(root.toString(), JSON);
                Request request = new Request.Builder()
                    .url(requestUrl)
                    .addHeader("Authorization", config.getKey())
                    .addHeader("Content-Type", "application/json")
                    .post(body)
                    .build();

                try (Response response = client.newCall(request).execute()) {
                    if (!response.isSuccessful()) {
                        String errorBody = response.body() != null ? response.body().string() : "No error body";
                        throw new IOException(String.format("Request failed with code %d: %s", 
                            response.code(), errorBody));
                    }

                    JsonNode jsonResponse = mapper.readTree(response.body().string());
                    return jsonResponse.path("choices").get(0).path("message").path("content").asText();
                }
            } catch (Exception e) {
                Msg.error(this, "Error making chat request: " + e.getMessage());
                throw new RuntimeException(e);
            }
        });
    }

    @Override
    public void dispose() {
        // Close connections
        if (client != null) {
            client.dispatcher().executorService().shutdown();
            client.connectionPool().evictAll();
        }
    }
}
