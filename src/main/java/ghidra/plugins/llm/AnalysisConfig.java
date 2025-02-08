package ghidra.plugins.llm;

import java.util.Map;
import java.util.HashMap;

/**
 * Configuration for analysis operations including recursive analysis and model selection.
 */
public class AnalysisConfig {
    private boolean recursiveAnalysis;
    private boolean recursiveRenaming;
    private boolean renameSimilarFunctions;
    private boolean ignoreRenamed;
    private int recursionDepth;
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
        this.renameSimilarFunctions = false;
        this.ignoreRenamed = false;
        this.recursionDepth = 0; // 0 = infinite
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
     * Sets whether automatic renaming of similar functions is enabled.
     * @param enabled true to enable similar function renaming
     */
    public void setRenameSimilarFunctions(boolean enabled) {
        this.renameSimilarFunctions = enabled;
    }

    /**
     * Gets whether automatic renaming of similar functions is enabled.
     * @return true if similar function renaming is enabled
     */
    public boolean isRenameSimilarFunctions() {
        return renameSimilarFunctions;
    }

    /**
     * Sets whether to ignore already renamed functions.
     * @param enabled true to ignore functions not starting with FUN_
     */
    public void setIgnoreRenamed(boolean enabled) {
        this.ignoreRenamed = enabled;
    }

    /**
     * Gets whether to ignore already renamed functions.
     * @return true if ignoring functions not starting with FUN_
     */
    public boolean isIgnoreRenamed() {
        return ignoreRenamed;
    }

    /**
     * Sets the maximum recursion depth (0 = infinite).
     * @param depth the maximum recursion depth
     */
    public void setRecursionDepth(int depth) {
        this.recursionDepth = depth;
    }

    /**
     * Gets the maximum recursion depth (0 = infinite).
     * @return the maximum recursion depth
     */
    public int getRecursionDepth() {
        return recursionDepth;
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
