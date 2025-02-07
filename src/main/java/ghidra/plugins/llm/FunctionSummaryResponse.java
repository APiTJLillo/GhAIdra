package ghidra.plugins.llm;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public class FunctionSummaryResponse {
    private String summary;
    private Details details;
    private String error;

    public static class Details {
        private String purpose;
        private String algorithmicPatterns;
        private String securityImplications;

        public String getPurpose() {
            return purpose;
        }

        public void setPurpose(String purpose) {
            this.purpose = purpose;
        }

        public String getAlgorithmicPatterns() {
            return algorithmicPatterns;
        }

        public void setAlgorithmicPatterns(String algorithmicPatterns) {
            this.algorithmicPatterns = algorithmicPatterns;
        }

        public String getSecurityImplications() {
            return securityImplications;
        }

        public void setSecurityImplications(String securityImplications) {
            this.securityImplications = securityImplications;
        }
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public Details getDetails() {
        return details;
    }

    public void setDetails(Details details) {
        this.details = details;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }

    public boolean isValid() {
        return summary != null && !summary.isEmpty() && details != null;
    }
}
