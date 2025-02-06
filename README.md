# Azure AI Assistant Plugin for Ghidra

A Ghidra plugin that uses Azure OpenAI services to analyze and improve function understanding.

## Features

- Function Analysis: Get detailed explanations of function behavior and purpose
- Smart Renaming: Get AI-powered suggestions for function and variable names
- Multiple Model Support: 
  - Azure OpenAI
  - Azure DeepSeek
- Recursive Analysis: Option to analyze called functions recursively
- Configurable Settings: Temperature, max tokens, and model selection

## Prerequisites

1. Ghidra 11.2.1 or later
2. Java Development Kit (JDK) 17 or later
3. Azure OpenAI Service access with API key

## Building

1. Set your Ghidra installation directory:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.2.1
```

2. Build the plugin:
```bash
./gradlew distributeExtension
```

This will create: `dist/ghidra_11.2.1_PUBLIC_YYYYMMDD_ghidra-azure-plugin.zip`

## Installation

1. Open Ghidra
2. File -> Install Extensions
3. Press the "+" button
4. Navigate to the built zip file in the dist directory and select it
5. Restart Ghidra

## Configuration

1. Go to Window > Azure AI Assistant
2. Click "Configure LLM" button
3. Add and configure your providers:
   
   For both providers:
   - Endpoint URL format: `https://{resource-name}.openai.azure.com/openai/deployments/{deployment-name}`
     - Example: `https://your-resource.openai.azure.com/openai/deployments/gpt-4o`
     - Do NOT include `/chat/completions` or `?api-version=` parameters
   - API Key: Your Azure OpenAI API key (header should be "api-key")
   - Configure model names and other settings in the dialog

## Usage

1. Open a program in Ghidra
2. Go to Window > Azure AI Assistant
3. Position your cursor within a function you want to analyze
4. Use the available actions:
   - Analyze Function: Get detailed analysis of function purpose and behavior
   - Analyze All Functions: Process all functions in the program
   - Rename Function: Get a suggested name that better describes the function's purpose
   - Rename Function & Variables: Get suggestions for both function and variable names

Configuration options:
- Enable Recursive Analysis: Also analyze functions called by the current function
- Enable Recursive Renaming: Suggest renames for called functions as well

## Troubleshooting

### Build Issues

If you see `GHIDRA_INSTALL_DIR is not defined!`:
1. Set the environment variable:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.2.1
```
2. Or specify it when running gradle:
```bash
GHIDRA_INSTALL_DIR=/path/to/ghidra_11.2.1 ./gradlew distributeExtension
```

### Runtime Issues

If you get authorization errors ("401: Unauthorized"):
1. Verify your Azure OpenAI endpoint URL:
   - Must include resource name and deployment name
   - Example: `https://your-resource.openai.azure.com/openai/deployments/APi-gpt-4o`
   - The plugin will automatically handle adding chat/completions and api-version
2. Make sure you're using the correct API key from Azure
3. Check that your model deployment is active and accessible
4. Try the endpoint URL in Postman to verify it works

## License

Apache License 2.0
