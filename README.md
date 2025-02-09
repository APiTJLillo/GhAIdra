# Azure AI Assistant Plugin for Ghidra

A Ghidra plugin that uses Azure OpenAI services to analyze and improve function understanding.

## Features

### Core Features
- Function Analysis: Get detailed explanations of function behavior and purpose
- Smart Renaming: Get AI-powered suggestions for function and variable names
- PCODE Simulation: Simulate function execution using Ghidra's PCODE system

### Analysis Features
- Multiple Model Support: 
  - Azure OpenAI
  - Azure DeepSeek
- Recursive Analysis: Option to analyze called functions recursively
- Similar Function Identification: Find and rename functions with similar patterns
- Progress Tracking: Visual feedback for long-running operations
- Batch Processing: Analyze or rename multiple functions at once

### UI Improvements
- Side-by-side Analysis View:
  - Analysis options panel on the left
  - Output display on the right
  - Progress tracking with visual indicators
- Tabbed Interface:
  - Analysis tab for LLM-based analysis
  - Simulation tab for PCODE execution
  - Easy switching between modes
- Progress Feedback:
  - Progress bar for batch operations
  - Detailed status updates
  - Clear operation state indicators

### Project Context Features
- Define application-specific context for more accurate analysis:
  - Technology stack and frameworks
  - Architecture patterns
  - Common code patterns
  - Domain-specific terminology
- Context-aware analysis:
  - Uses project context for better understanding
  - Shows function relationships
  - Identifies pattern matches

### Operation Controls
- Operation State Management:
  - Clear status indicators
  - Operation progress tracking
  - Batch operation support
- Configuration Options:
  - Model selection
  - Temperature and token settings
  - Analysis depth control
  - Simulation parameters

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

### Basic Operations
1. Open a program in Ghidra
2. Go to Window > Azure AI Assistant
3. Position your cursor within a function
4. Choose an operation:
   - Analyze Function: Get detailed analysis
   - Analyze All Functions: Process entire program
   - Rename Function: Get name suggestions
   - Rename Function & Variables: Full rename suggestions
   - Simulate Function: Run PCODE simulation

### Configuration Options
- Analysis Settings:
  - Enable Recursive Analysis
  - Enable Recursive Renaming
  - Auto-rename Similar Functions
  - Set Analysis Depth
- Project Context:
  - Project Name/Type
  - Technology Stack
  - Architecture Patterns
  - Domain Terms
  - Code Patterns

### Example Project Context Setup
```
Project Description:
Modern game client application
Uses Gamebryo engine and LuaPlus
Event-driven architecture with custom networking

Common Patterns:
- Event handler registration
- Network packet processing
- UI widget initialization
- Resource management

Domain Terms:
- Gamebryo: 3D game engine
- LuaPlus: Scripting system
- PacketHandler: Network message processor

Contextual Hints:
- Network packets use custom headers
- UI follows MVC pattern
- Resources loaded asynchronously
```

### Simulation Usage
1. Switch to Simulation tab
2. Configure parameters:
   - Input values
   - Memory state
   - Execution limits
3. Run simulation
4. Review results in output panel

## Troubleshooting

### Build Issues
If GHIDRA_INSTALL_DIR is not defined:
```bash
export GHIDRA_INSTALL_DIR=/path/to/ghidra_11.2.1
# or
GHIDRA_INSTALL_DIR=/path/to/ghidra_11.2.1 ./gradlew distributeExtension
```

### Common Issues
- Authentication Errors (401):
  1. Verify endpoint URL format
  2. Check API key
  3. Validate model deployment
  4. Test in Postman
- UI Responsiveness:
  1. Wait for operations to complete
  2. Use Clear Output to reset
  3. Process large programs in batches
- Analysis Quality:
  1. Ensure project context is set
  2. Configure appropriate model
  3. Adjust temperature settings

## License

Apache License 2.0
