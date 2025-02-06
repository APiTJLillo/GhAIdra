package azure;

import com.azure.ai.openai.OpenAIClient;
import com.azure.ai.openai.OpenAIClientBuilder;
import com.azure.ai.openai.models.*;
import com.azure.core.credential.AzureKeyCredential;

import java.util.ArrayList;
import java.util.List;

public class TestAzureConnection {
    public static void main(String[] args) {
        String azureOpenaiKey = System.getenv("AZURE_OPENAI_KEY");
        String endpoint = System.getenv("AZURE_OPENAI_ENDPOINT");
        String deploymentOrModelId = "deepseek-r1";

        // Print environment variables for debugging
        System.out.println("API Key: " + azureOpenaiKey);
        System.out.println("Endpoint: " + endpoint);

        OpenAIClient client = new OpenAIClientBuilder()
            .endpoint(endpoint)
            .credential(new AzureKeyCredential(azureOpenaiKey))
            .buildClient();

        System.out.println("Client created successfully");

        List<ChatMessage> messages = new ArrayList<>();
        messages.add(new ChatMessage(ChatRole.USER, "When was Microsoft founded?"));

        ChatCompletionsOptions options = new ChatCompletionsOptions(messages)
            .setMaxTokens(1000)
            .setTemperature(0.3);

            ChatCompletions completions =
                client.getChatCompletions(deploymentOrModelId, new ChatCompletionsOptions(messages));

        System.out.printf("Model ID=%s is created at %s.%n", completions.getId(), completions.getCreatedAt());
        for (ChatChoice choice : completions.getChoices()) {
            System.out.printf("Index: %d, Content: %s.%n", choice.getIndex(), choice.getMessage().getContent());
        }

        CompletionsUsage usage = completions.getUsage();
        System.out.printf("Usage: number of prompt token is %d, "
                + "number of completion token is %d, and number of total tokens in request and response is %d.%n",
            usage.getPromptTokens(), usage.getCompletionTokens(), usage.getTotalTokens());
    }
}
