package ghidra.plugins.llm;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Stores contextual information about the current project to help guide LLM analysis.
 */
public class ProjectContext {
    private String projectName;
    private String projectType;
    private String description;
    private List<String> commonPatterns;
    private Map<String, String> domainTerminology;
    private Map<String, String> contextualHints;

    public ProjectContext() {
        this.commonPatterns = new ArrayList<>();
        this.domainTerminology = new HashMap<>();
        this.contextualHints = new HashMap<>();
        this.description = "";
    }

    /**
     * Sets the project name.
     * @param name the project name
     */
    public void setProjectName(String name) {
        this.projectName = name;
    }

    /**
     * Gets the project name.
     * @return the project name
     */
    public String getProjectName() {
        return projectName;
    }

    /**
     * Sets the project type.
     * @param type the project type (e.g., "Game Client", "Device Driver")
     */
    public void setProjectType(String type) {
        this.projectType = type;
    }

    /**
     * Sets the project description.
     * @param description detailed description of the project and its components
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Gets the project description.
     * @return the project description
     */
    public String getDescription() {
        return description;
    }

    /**
     * Gets the project type.
     * @return the project type
     */
    public String getProjectType() {
        return projectType;
    }

    /**
     * Adds a common pattern to look for during analysis.
     * @param pattern description of the pattern
     */
    public void addCommonPattern(String pattern) {
        commonPatterns.add(pattern);
    }

    /**
     * Gets the list of common patterns.
     * @return list of patterns
     */
    public List<String> getCommonPatterns() {
        return new ArrayList<>(commonPatterns);
    }

    /**
     * Adds or updates a domain-specific term mapping.
     * @param term the technical term
     * @param description plain language description
     */
    public void setDomainTerm(String term, String description) {
        domainTerminology.put(term, description);
    }

    /**
     * Gets the domain terminology mappings.
     * @return map of terms to descriptions
     */
    public Map<String, String> getDomainTerminology() {
        return new HashMap<>(domainTerminology);
    }

    /**
     * Adds or updates a contextual hint.
     * @param key the hint category/key
     * @param value the hint value/description
     */
    public void setContextualHint(String key, String value) {
        contextualHints.put(key, value);
    }

    /**
     * Gets the contextual hints.
     * @return map of hint categories to values
     */
    public Map<String, String> getContextualHints() {
        return new HashMap<>(contextualHints);
    }

    /**
     * Creates a formatted context string for inclusion in LLM prompts.
     * @return formatted context string
     */
    public String toPromptContext() {
        StringBuilder context = new StringBuilder();
        context.append("Project Context:\n");
        
        if (projectName != null) {
            context.append("Project Name: ").append(projectName).append("\n");
        }
        if (projectType != null) {
            context.append("Project Type: ").append(projectType).append("\n");
        }
        if (description != null && !description.trim().isEmpty()) {
            context.append("\nProject Description:\n").append(description.trim()).append("\n");
        }

        if (!commonPatterns.isEmpty()) {
            context.append("\nCommon Patterns to Consider:\n");
            for (String pattern : commonPatterns) {
                context.append("- ").append(pattern).append("\n");
            }
        }

        if (!domainTerminology.isEmpty()) {
            context.append("\nDomain Terminology:\n");
            domainTerminology.forEach((term, desc) ->
                context.append("- ").append(term).append(": ").append(desc).append("\n")
            );
        }

        if (!contextualHints.isEmpty()) {
            context.append("\nAdditional Context:\n");
            contextualHints.forEach((key, value) ->
                context.append("- ").append(key).append(": ").append(value).append("\n")
            );
        }

        return context.toString();
    }
}
