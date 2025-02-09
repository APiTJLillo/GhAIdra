package ghidra.plugins.llm;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.util.task.TaskMonitor;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Language;
import ghidra.util.Msg;
import ghidra.app.emulator.EmulatorHelper;
import java.math.BigInteger;

import java.util.*;

/**
 * Handles PCODE simulation of functions using Ghidra's emulation capabilities.
 */
public class PCODESimulator {
    private final Program program;
    private EmulatorHelper emulator;
    private DecompInterface decompiler;

    public PCODESimulator(Program program) {
        this.program = program;
        initializeEmulator();
        initializeDecompiler();
    }

    private void initializeEmulator() {
        emulator = new EmulatorHelper(program);
    }

    private void initializeDecompiler() {
        decompiler = new DecompInterface();
        decompiler.openProgram(program);
    }

    /**
     * Simulates a function with AI-suggested inputs.
     * @param function The function to simulate
     * @param inputs Map of parameter names to their suggested values
     * @return SimulationResult containing the execution trace and outputs
     */
    public SimulationResult simulate(Function function, Map<String, Long> inputs) {
        SimulationResult result = new SimulationResult();
        
        try {
            // Get function entry point
            Address entry = function.getEntryPoint();
            Language language = program.getLanguage();
            Register pc = language.getProgramCounter();
            emulator.writeRegister(pc, entry.getOffset());

            // Set up input parameters
            setupFunctionParameters(function, inputs);

            // Execute until return or timeout
            long maxInstructions = 10000; // Prevent infinite loops
            long instructionCount = 0;
            
            while (instructionCount < maxInstructions) {
                Address currentAddress = emulator.getExecutionAddress();
                
                // Check if we've returned from the function
                if (!function.getBody().contains(currentAddress)) {
                    break;
                }

                // Execute next instruction
                boolean success = emulator.step(TaskMonitor.DUMMY);
                if (!success) {
                    result.addError("Failed to execute instruction at " + currentAddress);
                    break;
                }

                // Record execution trace
                recordTrace(result, currentAddress);
                
                instructionCount++;
            }

            // Capture final register states and memory values
            captureOutputState(result, function);

        } catch (Exception e) {
            result.addError("Simulation error: " + e.getMessage());
        }

        return result;
    }

    private void setupFunctionParameters(Function function, Map<String, Long> inputs) {
        // Get calling convention for parameter setup
        ghidra.program.model.listing.Parameter[] parameters = function.getParameters();
        
        for (ghidra.program.model.listing.Parameter param : parameters) {
            String name = param.getName();
            if (inputs.containsKey(name)) {
                try {
                    // Handle different parameter storage types
                    if (param.isRegisterVariable()) {
                        Register reg = param.getRegister();
                        emulator.writeRegister(reg, inputs.get(name));
                    } else if (param.isStackVariable()) {
                        // For stack parameters, we need to write to the appropriate stack location
                        long offset = param.getStackOffset();
                        // Calculate stack pointer address
                        Address stackPtr = program.getAddressFactory().getDefaultAddressSpace().getAddress(0L);
                        emulator.writeMemoryValue(stackPtr.add(offset), param.getDataType().getLength(), inputs.get(name));
                    }
                } catch (Exception e) {
                    // Log error but continue with other parameters
                    Msg.error(this, "Error setting parameter " + name + ": " + e.getMessage());
                }
            }
        }
    }

    private void recordTrace(SimulationResult result, Address address) {
        try {
            // Get instruction at current address
            var instruction = program.getListing().getInstructionAt(address);
            if (instruction != null) {
                // Record instruction and register states
                result.addTraceEntry(new TraceEntry(
                    address,
                    instruction.toString(),
                    getCurrentRegisterState()
                ));
            }
        } catch (Exception e) {
            result.addError("Error recording trace at " + address + ": " + e.getMessage());
        }
    }

    private Map<String, Long> getCurrentRegisterState() {
        Map<String, Long> registerState = new HashMap<>();
        List<Register> registers = program.getLanguage().getRegisters();
        
        for (Register reg : registers) {
            if (reg.isBaseRegister()) { // Only record base registers
                try {
                    BigInteger value = emulator.readRegister(reg);
                    if (value != null) {
                        registerState.put(reg.getName(), value.longValue());
                    }
                } catch (Exception e) {
                    // Skip registers that can't be read
                    continue;
                }
            }
        }
        
        return registerState;
    }

    private void captureOutputState(SimulationResult result, Function function) {
        // Capture return value if applicable
        if (!function.hasNoReturn()) {
            try {
                // Get return register based on calling convention
                Register returnReg = function.getReturn().getRegister();
                if (returnReg != null) {
                    BigInteger value = emulator.readRegister(returnReg);
                    if (value != null) {
                        result.setReturnValue(value.longValue());
                    }
                }
            } catch (Exception e) {
                result.addError("Error capturing return value: " + e.getMessage());
            }
        }

        // Capture final memory state for output parameters
        for (ghidra.program.model.listing.Parameter param : function.getParameters()) {
            if (param.getDataType() instanceof PointerDataType) {
                try {
                    // For pointer parameters, capture the memory they point to
                    if (param.isRegisterVariable()) {
                        Register reg = param.getRegister();
                        BigInteger value = emulator.readRegister(reg);
                        long pointerValue = value.longValue();
                        // Read some bytes from the pointed memory
                        Address pointerAddr = program.getAddressFactory().getAddress(Long.toHexString(pointerValue));
                        byte[] memory = new byte[16]; // Adjust size as needed
                        for (int i = 0; i < memory.length; i++) {
                            memory[i] = (byte)emulator.readMemoryByte(pointerAddr.add(i));
                        }
                        result.addOutputParameter(param.getName(), memory);
                    }
                } catch (Exception e) {
                    result.addError("Error capturing output parameter " + param.getName() + ": " + e.getMessage());
                }
            }
        }
    }

    /**
     * Clean up resources.
     */
    public void dispose() {
        if (emulator != null) {
            emulator.dispose();
            emulator = null;
        }
        if (decompiler != null) {
            decompiler.dispose();
            decompiler = null;
        }
    }

    /**
     * Represents a single step in the execution trace.
     */
    public static class TraceEntry {
        private final Address address;
        private final String instruction;
        private final Map<String, Long> registerState;

        public TraceEntry(Address address, String instruction, Map<String, Long> registerState) {
            this.address = address;
            this.instruction = instruction;
            this.registerState = registerState;
        }

        public Address getAddress() {
            return address;
        }

        public String getInstruction() {
            return instruction;
        }

        public Map<String, Long> getRegisterState() {
            return registerState;
        }
    }

    /**
     * Contains the results of a function simulation.
     */
    public static class SimulationResult {
        private final List<TraceEntry> executionTrace;
        private final List<String> errors;
        private final Map<String, byte[]> outputParameters;
        private Long returnValue;

        public SimulationResult() {
            executionTrace = new ArrayList<>();
            errors = new ArrayList<>();
            outputParameters = new HashMap<>();
        }

        public void addTraceEntry(TraceEntry entry) {
            executionTrace.add(entry);
        }

        public void addError(String error) {
            errors.add(error);
        }

        public void addOutputParameter(String name, byte[] value) {
            outputParameters.put(name, value);
        }

        public void setReturnValue(Long value) {
            returnValue = value;
        }

        public List<TraceEntry> getExecutionTrace() {
            return executionTrace;
        }

        public List<String> getErrors() {
            return errors;
        }

        public Map<String, byte[]> getOutputParameters() {
            return outputParameters;
        }

        public Long getReturnValue() {
            return returnValue;
        }

        public boolean hasErrors() {
            return !errors.isEmpty();
        }
    }
}
