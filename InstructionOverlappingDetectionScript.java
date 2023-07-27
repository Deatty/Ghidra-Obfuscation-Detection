//
//@author 
//@category 
//@keybinding
//@menupath
//@toolbar

import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.DefaultAddressFactory;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.task.TaskMonitor;

public class InstructionOverlappingDetectionScript extends GhidraScript {
	Listing listing;

	@Override
	protected void run() throws Exception {
		listing = currentProgram.getListing();
		
		FunctionIterator functionIterator = currentProgram.getFunctionManager().getFunctionsNoStubs(true);
		Function function;
		
		while (functionIterator.hasNext() && !monitor.isCancelled()) {
			function = functionIterator.next();
			Boolean overlapps = hasOverlappingInstructions(function);
			if(overlapps) printf("Has overlapping instructions: %b\n", overlapps);
		}
		
//		function = getFunctionContaining(currentAddress);
//		Boolean overlapps = hasOverlappingInstructions(function);
//		printf("Has overlapping instructions: %b\n", overlapps);
		
	}
	
	private Boolean hasOverlappingInstructions(Function function) {
		AddressSet instrBytes = new AddressSet();
		AddressSet jumpTargetSet = new AddressSet();
		Boolean overlapps = false;
		AddressSetView addressSetView = function.getBody();
		InstructionIterator instrIt = listing.getInstructions(addressSetView, true);
		
		while (instrIt.hasNext() && !monitor.isCancelled()) {
			Instruction instr = instrIt.next();
			
			if (instr.getLength() > 1) {
				instrBytes.addRange(instr.getMinAddress().add(1), instr.getMaxAddress());
			} else {
				continue;
			}
			String mnem = instr.getMnemonicString();
			
			if (mnem.startsWith("J")) {
//				String targetAddress = instr.getDefaultOperandRepresentation(0);

				PcodeOp[] pcodes = instr.getPcode();
				for(int i = 0; i<pcodes.length; i++) {
					String pcodeMnem = pcodes[i].getMnemonic();
					if(pcodeMnem.matches("BRANCH|CBRANCH")) {
						Varnode node = pcodes[i].getInput(0);
						Address pcodeTargetAddrres = node.getAddress();
						jumpTargetSet.add(pcodeTargetAddrres);
//						printf("pcode[%s] jump target: 0x%s\n", pcodeMnem, pcodeTargetAddrres);
					}

				}
//				printf("%s at 0x%s target %s\n",mnem, instr.getMinAddress(), targetAddress);
//				Address ad = instr.getMinAddress();
//				try {
//					ad = ad.getAddress(targetAddress);
//				} catch (AddressFormatException e) {
//					continue;
//				}
//				jumpTargetSet.add(ad);
			}
		}

		AddressIterator addItr =  jumpTargetSet.getAddresses(true);
		
		while (addItr.hasNext() && !monitor.isCancelled()) {
			Address addr = addItr.next();
			if (instrBytes.getRangeContaining(addr) != null) {
				overlapps = true;
				printf("overlap at : 0x%s\n", addr);
			}
		}
		return overlapps;

	}
	
	
	
}
