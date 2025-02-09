package ghidra.plugins.llm.providers.openai;

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
import ghidra.plugins.llm.RenamingResponse;
import ghidra.plugins.llm.FunctionSummaryResponse;
import ghidra.util.Msg;

/**
 * OpenAI direct API provider implementation.
 */
public class OpenAIProvider implements LLMProvider {
    private OkHttpClient client;
    private OpenAIConfig config;
    private final ObjectMapper mapper = new ObjectMapper();
    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    private static final String API_URL = "https://api.openai.com/v1/chat/completions";
    private static final int TIMEOUT_SECONDS = 120;
    
    private static final String RENAMING_SYSTEM_PROMPT = """
        You are an expert code analyzer. Your task is to suggest ONE best clear and descriptive name for each function and variable.
        IMPORTANT: Return raw JSON only, without any markdown formatting, code blocks, or additional text.
        Format your response exactly like this:
        {
            "functionName": "suggestedName",
            "variableNames": {
                "oldVarName1": "newVarName1",
                "oldVarName2": "newVarName2"
            }
        }
        Rules:
        - Return raw JSON only, no markdown, no code blocks
        - For each function or variable, provide EXACTLY ONE best name suggestion
        - Do not provide multiple options or alternatives
        - Use camelCase for variable names and PascalCase for function names
        - Names should be clear, descriptive, and concise
        - Focus on making names that accurately reflect their purpose
        - Use clear, descriptive names without unnecessary prefixes
        - For pointer variables, use names that indicate what they point to
        - Names should reflect the variable's purpose and type naturally
        """;

    private static final String ANALYSIS_SYSTEM_PROMPT = """
        You are an expert reverse engineer analyzing decompiled code.
        IMPORTANT: Return raw JSON only, without any markdown formatting, code blocks, or additional text.
        Format your response exactly like this:
        {
            "summary": "One-line summary of function's purpose",
            "details": {
                "purpose": "Detailed description of function's purpose",
                "algorithmicPatterns": "Key algorithms or patterns used",
                "securityImplications": "Security considerations"
            }
        }
        Rules:
        - Return raw JSON only, no markdown, no code blocks
        - Be concise and specific
        - Focus on the core functionality and key behaviors
        - Include important security implications and potential vulnerabilities
        - Summarize any notable algorithmic patterns or techniques
        """;

    @Override
    public void configure(LLMConfig config) {
        if (!(config instanceof OpenAIConfig)) {
            throw new IllegalArgumentException("Expected OpenAIConfig");
        }
        this.config = (OpenAIConfig) config;
        setupClient();
    }

    private void setupClient() {
        if (!config.isValid()) {
            throw new IllegalStateException("Invalid OpenAI configuration");
        }

        this.client = new OkHttpClient.Builder()
            .connectTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .readTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .writeTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
            .build();
    }

    private static final int MAX_RETRIES = 3;

    @Override
    public CompletableFuture<RenamingResponse> analyze(String prompt) {
        return makeChatRequestWithRetry(prompt, RENAMING_SYSTEM_PROMPT, RenamingResponse.class);
    }

    @Override
    public CompletableFuture<FunctionSummaryResponse> analyzeFunction(String prompt) {
        return makeChatRequestWithRetry(prompt, ANALYSIS_SYSTEM_PROMPT, FunctionSummaryResponse.class);
    }

    private <T> CompletableFuture<T> makeChatRequestWithRetry(final String prompt, String systemPrompt, Class<T> responseClass) {
        return CompletableFuture.supplyAsync(() -> {
            int retryCount = 0;
            String currentPrompt = prompt;

            while (retryCount < MAX_RETRIES) {
                try {
                    ObjectNode root = mapper.createObjectNode();
                    root.put("model", config.getModel());
                    root.put("temperature", config.getTemperature());
                    root.put("max_tokens", config.getMaxTokens());

                    ArrayNode messages = root.putArray("messages");
                    ObjectNode systemMessage = messages.addObject();
                    systemMessage.put("role", "system");
                    systemMessage.put("content", systemPrompt);

                    ObjectNode userMessage = messages.addObject();
                    userMessage.put("role", "user");
                    userMessage.put("content", currentPrompt);

                    Msg.debug(this, String.format("Making request to OpenAI API (model: %s)", config.getModel()));

                    RequestBody body = RequestBody.create(root.toString(), JSON);
                    Request request = new Request.Builder()
                        .url(API_URL)
                        .addHeader("Authorization", "Bearer " + config.getApiKey())
                        .addHeader("Content-Type", "application/json")
                        .post(body)
                        .build();

                    try (Response response = client.newCall(request).execute()) {
                        if (!response.isSuccessful()) {
                            String errorBody = response.body() != null ? response.body().string() : "No error body";
                            throw new IOException(String.format("Request failed with code %d: %s", 
                                response.code(), errorBody));
                        }

                        String responseContent = response.body().string();
                        JsonNode jsonResponse = mapper.readTree(responseContent);
                        String content = jsonResponse.path("choices").get(0).path("message").path("content").asText();
                        
                        // Clean up the response - remove markdown code blocks if present
                        content = content.replaceAll("```json\\s*", "")
                                      .replaceAll("```\\s*", "")
                                      .trim();

                        try {
                            T parsedResponse = mapper.readValue(content, responseClass);
                            
                            // Validate the response
                            if (parsedResponse instanceof RenamingResponse) {
                                RenamingResponse renamingResponse = (RenamingResponse) parsedResponse;
                                if (!renamingResponse.isValid()) {
                                    throw new IOException("Invalid renaming response format");
                                }
                            } else if (parsedResponse instanceof FunctionSummaryResponse) {
                                FunctionSummaryResponse summaryResponse = (FunctionSummaryResponse) parsedResponse;
                                if (!summaryResponse.isValid()) {
                                    throw new IOException("Invalid function summary response format");
                                }
                            }
                            
                            return parsedResponse;
                        } catch (Exception e) {
                            if (retryCount < MAX_RETRIES - 1) {
                                // Add error context to the next attempt
                                final String errorMsg = e.getMessage();
                                currentPrompt = String.format(
                                    "Previous response was invalid. Please fix the JSON format and try again.\n" +
                                    "Error: %s\n\nOriginal prompt:\n%s",
                                    errorMsg, prompt
                                );
                                retryCount++;
                                continue;
                            }
                            throw e;
                        }
                    }
                } catch (Exception e) {
                    if (retryCount < MAX_RETRIES - 1) {
                        retryCount++;
                        continue;
                    }
                    Msg.error(this, "Error making chat request after " + MAX_RETRIES + " retries: " + e.getMessage());
                    throw new RuntimeException(e);
                }
            }
            throw new RuntimeException("Failed to get valid response after " + MAX_RETRIES + " retries");
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
