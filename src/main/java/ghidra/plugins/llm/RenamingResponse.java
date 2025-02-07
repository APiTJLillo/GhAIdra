package ghidra.plugins.llm;

import java.util.HashMap;
import java.util.Map;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class RenamingResponse {
    private String functionName;
    private Map<String, String> variableNames;
    private String error;

    public RenamingResponse() {
        this.variableNames = new HashMap<>();
    }

    public String getFunctionName() {
        return functionName;
    }

    public void setFunctionName(String functionName) {
        this.functionName = functionName;
    }

    public Map<String, String> getVariableNames() {
        return variableNames;
    }

    public void setVariableNames(Map<String, String> variableNames) {
        this.variableNames = variableNames;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public boolean isValid() {
        return functionName != null && !functionName.isEmpty();
    }

    public void addVariableRename(String oldName, String newName) {
        if (oldName != null && newName != null) {
            variableNames.put(oldName, newName);
        }
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (error != null) {
            return "Error: " + error;
        }

        sb.append("Function name: ").append(functionName).append("\n");
        if (!variableNames.isEmpty()) {
            sb.append("Variable renames:\n");
            variableNames.forEach((oldName, newName) ->
                sb.append("  ").append(oldName).append(" → ").append(newName).append("\n")
            );
        }
        return sb.toString();
    }
}
