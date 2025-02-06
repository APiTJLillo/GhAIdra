package ghidra.plugins.llm.ui;

/**
 * Interface for components that need to be notified of UI updates
 */
public interface UpdateListener {
    /**
     * Called when a UI update occurs
     */
    void onUpdate();
}
