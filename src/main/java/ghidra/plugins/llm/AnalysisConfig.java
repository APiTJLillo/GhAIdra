package ghidra.plugins.llm;

import java.util.Map;
import java.util.HashMap;

/**
 * Configuration for analysis operations including recursive analysis and model selection.
 */
public class AnalysisConfig {
    private boolean recursiveAnalysis;
    private boolean recursiveRenaming;
    private Map<Integer, String> depthModelMap;  // Maps depth level to model ID
    private Map<OperationType, String> operationModelMap;  // Maps operation type to model ID

    public enum OperationType {
        RENAME_FUNCTION,
        RENAME_VARIABLE,
        COMMENT_FUNCTION,
        COMMENT_VARIABLE
    }

    public AnalysisConfig() {
        this.recursiveAnalysis = false;
        this.recursiveRenaming = false;
        this.depthModelMap = new HashMap<>();
        this.operationModelMap = new HashMap<>();
    }

    /**
     * Sets whether recursive analysis is enabled.
     * @param enabled true to enable recursive analysis
     */
    public void setRecursiveAnalysis(boolean enabled) {
        this.recursiveAnalysis = enabled;
    }

    /**
     * Sets whether recursive renaming is enabled.
     * @param enabled true to enable recursive renaming
     */
    public void setRecursiveRenaming(boolean enabled) {
        this.recursiveRenaming = enabled;
    }

    /**
     * Gets whether recursive analysis is enabled.
     * @return true if recursive analysis is enabled
     */
    public boolean isRecursiveAnalysis() {
        return recursiveAnalysis;
    }

    /**
     * Gets whether recursive renaming is enabled.
     * @return true if recursive renaming is enabled
     */
    public boolean isRecursiveRenaming() {
        return recursiveRenaming;
    }

    /**
     * Sets the model to use for a specific depth level.
     * @param depth the depth level
     * @param modelId the ID of the model to use
     */
    public void setModelForDepth(int depth, String modelId) {
        depthModelMap.put(depth, modelId);
    }

    /**
     * Gets the model ID for a specific depth level.
     * @param depth the depth level
     * @return the model ID, or null if not specifically set
     */
    public String getModelForDepth(int depth) {
        return depthModelMap.get(depth);
    }

    /**
     * Sets the model to use for a specific operation type.
     * @param operation the operation type
     * @param modelId the ID of the model to use
     */
    public void setModelForOperation(OperationType operation, String modelId) {
        operationModelMap.put(operation, modelId);
    }

    /**
     * Gets the model ID for a specific operation type.
     * @param operation the operation type
     * @return the model ID, or null if not specifically set
     */
    public String getModelForOperation(OperationType operation) {
        return operationModelMap.get(operation);
    }
}
