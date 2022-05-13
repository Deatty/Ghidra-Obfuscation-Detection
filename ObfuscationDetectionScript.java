//Collection of simple heuristics that can detect obfuscated code
//@author Spiros
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.graph.GDirectedGraph;
import ghidra.graph.GEdge;
import ghidra.graph.GraphAlgorithms;
import ghidra.graph.GraphFactory;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.graph.CodeBlockEdge;
import ghidra.program.model.block.graph.CodeBlockVertex;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.util.CyclomaticComplexity;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;


public class ObfuscationDetectionScript extends GhidraScript {
	public static CyclomaticComplexity cyclomaticComplexity = new CyclomaticComplexity();
	public static DataSet dataSet;
	public static BasicBlockModel basicBlockModel;
	public static Heuristics heuristics;

	@Override
	protected void run() throws Exception {
		if(currentProgram == null) {
			printerr("no current program");
			return;
		}
		basicBlockModel = new BasicBlockModel(currentProgram);
		dataSet = new DataSet();
		heuristics = new Heuristics();
		Function currentFunction = getFunctionContaining(currentAddress);
		
		try {
			if((currentFunction == null)) {
				File outputFolder;
				List<String> choices = new ArrayList<>();
			
				choices.add("only print");
				choices.add("only export");
				choices.add("print and export");
				String choice = askChoice("Choose", "What do you want this script to do?", choices, "only print");

				analyzeAllFunctions();

				switch(choice) {
				case("only print"):
					dataSet.sortAndPrint();
					break;
				case("only export"):
					outputFolder = askDirectory("Select a folder to save results", "Choose");
					exportToCsvFile(outputFolder);
					break;
				case("print and export"):
					dataSet.sortAndPrint();
					outputFolder = askDirectory("Select a folder to save results", "Choose");
					exportToCsvFile(outputFolder);
					break;
				}
				return;
			}
			FunctionData functionData = analyzeFunction(currentFunction);
			functionData.printData();

		} catch(CancelledException e) {
			printerr("Operation cancelled!");
		}
	}
	
	private FunctionData analyzeFunction(Function function)
			throws CancelledException {
		int averageInstructions = heuristics.calcAverageInstructionsPerBlock(function);
		int complexityScore = cyclomaticComplexity.calculateCyclomaticComplexity(function, monitor);
		double entropy = heuristics.calcEntropy(function);
		double flatteningScore = heuristics.calcFlatteningScore(function);
		
		FunctionData functionData = new FunctionData(function.getName(), 
				function.getEntryPoint(),
				averageInstructions,
				complexityScore,
				flatteningScore,
				entropy);
		
		return functionData;
	}
	
	private void analyzeAllFunctions() throws CancelledException {
		FunctionIterator functionIterator =  currentProgram.getFunctionManager().getFunctionsNoStubs(true);

		while(functionIterator.hasNext()) {
			if(monitor.isCancelled()) {
				break;
			}
			Function function = functionIterator.next();
			FunctionData functionData = analyzeFunction(function);
			dataSet.getData().add(functionData);
		}
	}

	private void exportToCsvFile(File outputFolder) {
		FileWriter fileWriter;
		File outputFile = new File(outputFolder.getAbsolutePath()
				+ File.separator + currentProgram.getName() + "-ObfuscationDetection-Results.csv");
		try {
			fileWriter = new FileWriter(outputFile);
			String headers = String.join(", ", dataSet.getData().get(0).getFieldNames());
			fileWriter.write(headers + '\n');
			
			dataSet.sortByEntryPoint();
			for (FunctionData i : dataSet.getData()) {
				String line = String.join(", ", i.getData());
				fileWriter.write(line + '\n');
			}
			fileWriter.close();
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private class FunctionData {

		private String name;
		private Address entryPoint;
		private int averageInstructionsPerBlock;
		private int cyclomaticComplexityScore;
		private double flatteningScore;
		private double entropy;

		public FunctionData(String name, Address entryPoint, int averageInstructionsPerBlock,
				int cyclomaticComplexityScore, double flatteningScore, double entropy) {
			this.name = name;
			this.entryPoint = entryPoint;
			this.averageInstructionsPerBlock = averageInstructionsPerBlock;
			this.cyclomaticComplexityScore = cyclomaticComplexityScore;
			this.flatteningScore = flatteningScore;
			this.entropy = entropy;
		}

		public int getAverageInstructionsPerBlock() {
			return averageInstructionsPerBlock;
		}

		public int getCyclomaticComplexityScore() {
			return cyclomaticComplexityScore;
		}

		public double getFlatteningScore() {
			return flatteningScore;
		}

		public double getEntropy() {
			return entropy;
		}
		
		public Address getEntryPoint() {
			return entryPoint;
		}

		public String[] getFieldNames() {
			String[] fieldNames = { "Name", "Entry Point", "Average Instructions Per Block",
					"Cyclomatic Complexity", "Flattening Score", "Entropy"};
			return fieldNames;
		}

		public String[] getData() {
			String[] data = {name, entryPoint.toString(), String.valueOf(averageInstructionsPerBlock),
					String.valueOf(cyclomaticComplexityScore), String.valueOf(flatteningScore),
					String.valueOf(entropy)};
			return data;
		}

		public void printData(int index) {
			String[] strings = {"Average Instructions: %d", "Complexity Score: %d", "Flattening Score: %f",
					"Entropy: %f"};
			Object[] objects = {averageInstructionsPerBlock ,cyclomaticComplexityScore, flatteningScore, entropy};
			 
			printf("Function: %s  Address: 0x%s  " + strings[index] + "\n", name, entryPoint, objects[index]);
		}
		
		public void printData() {
			printf("Function: %s  Address: 0x%s  Average Instructions: %d  Complexity Score: %d  Flattening Score: %f  \n",
					name, entryPoint,averageInstructionsPerBlock ,cyclomaticComplexityScore, flatteningScore, entropy);

		}
	}
	
	private class DataSet {
		private ArrayList<FunctionData> data = new ArrayList<FunctionData>();

		public ArrayList<FunctionData> getData() {
			return data;
		}

		private void sortByAverageInstructions() {
			data.sort(Comparator.comparingInt(FunctionData::getAverageInstructionsPerBlock).reversed());
		}
		
		private void sortByCyclomaticComplexity() {
			data.sort(Comparator.comparingInt(FunctionData::getCyclomaticComplexityScore).reversed());
		}
		
		private void sortByFlatteningScore() {
			data.sort(Comparator.comparingDouble(FunctionData::getFlatteningScore).reversed());
		}
		
		private void sortByEntropy() {
			data.sort(Comparator.comparingDouble(FunctionData::getEntropy).reversed());
		}
		
		private void sortByEntryPoint() {
			data.sort(Comparator.comparing(FunctionData::getEntryPoint));
		}
		
		private void sortBy(int sort) {
			switch(sort) {
			case 0:
				sortByAverageInstructions();
				break;
			case 1: 
				sortByCyclomaticComplexity();
				break;
			case 2:
				sortByFlatteningScore();
				break;
			case 3:
				sortByEntropy();
				break;
			case 4:
				sortByEntryPoint();
				break;
			}
		}
		
		private void sortAndPrint() {
			String line = String.join("", Collections.nCopies(150, "-")) + "\n";
			print(line);
			for(int i = 0; i < 4; i++) {
				sortBy(i);
				printTop10(i);
				print(line);
			}
			
		}
		
		private void printTop10(int dataIndex) {
			int times = 10;
			if(data.size() < 10) {
				times = data.size();
			}
			for(int i = 0; i < times; i++) {
				data.get(i).printData(dataIndex);
			}
		}
	}

	public class Heuristics {
		
		public int countFunctionBlocks(Function function)
				throws CancelledException{
			CodeBlockIterator codeBlockIterator = basicBlockModel.getCodeBlocksContaining(function.getBody(), monitor);
			int numOfBlocks = 0;
			
			while(codeBlockIterator.hasNext()) {
				if(monitor.isCancelled()) {
					break;
				}
				numOfBlocks++;
				codeBlockIterator.next();
			}
			return numOfBlocks;
		}
		
		public int countFunctionInstructions(Function function) {
			AddressSetView addressSetView = function.getBody();
			Listing listing = currentProgram.getListing();
			InstructionIterator instructionIterator = listing.getInstructions(addressSetView, true);
			int numOfInstructions = 0;

			while(instructionIterator.hasNext()) {
				if(monitor.isCancelled()) {
					break;
				}
				numOfInstructions++;
				instructionIterator.next();
			}
			return numOfInstructions;
		}
		
		public int calcAverageInstructionsPerBlock(Function function) 
				throws CancelledException {
		    int numOfBlocks = countFunctionBlocks(function);
		    int numOfInstructions = countFunctionInstructions(function);
		    
		    if(numOfBlocks != 0) {
		    	return numOfInstructions/numOfBlocks;
		    }
		    return 0;
		}

		public double calcFlatteningScore(Function function)
				throws CancelledException {
			GDirectedGraph<CodeBlockVertex, CodeBlockEdge> controlFlowGraph
					= ControlFlowGraph.createControlFlowGraph(function, monitor);
			GDirectedGraph<CodeBlockVertex, GEdge<CodeBlockVertex>> dominanceTree
					= GraphAlgorithms.findDominanceTree(controlFlowGraph, monitor);
			Collection<CodeBlockVertex> nodes = controlFlowGraph.getVertices();
			Boolean hasBackEdge;
			Double score = 0.0;
			
			for(CodeBlockVertex node: nodes) {
				if(monitor.isCancelled()) {
					break;
				}
				Collection<CodeBlockVertex> collection = new ArrayList<CodeBlockVertex>();
				collection.add(node);
				Collection<CodeBlockVertex> dominatedNodes = GraphAlgorithms.getDescendants(dominanceTree, collection);
				for(CodeBlockVertex dominatedNode: dominatedNodes) {
					if(monitor.isCancelled()) {
						break;
					}
					hasBackEdge = controlFlowGraph.containsEdge(dominatedNode, node);
					if(!hasBackEdge) {
						continue;
					}
					score = Math.max(score, (double)dominatedNodes.size() / nodes.size());
				}
			}
			return score;
		}

		public double calcEntropy(Function function) {
			int numOfBytes = (int)function.getBody().getNumAddresses();
			double entropy = 0.0;
			try {
				byte[] bytes = getBytes(function.getEntryPoint(), numOfBytes);
			    HashMap<Byte, Integer> byteCounter = new HashMap<>();
			    for(byte i: bytes) {
					if(monitor.isCancelled()) {
						break;
					}
			    	if(byteCounter.containsKey(i)) {
			    		byteCounter.put(i, byteCounter.get(i)+1);
			    	} else {
			    		byteCounter.put(i, 1);
			    	}
			    }
			    for(Integer i: byteCounter.values()) {
					if(monitor.isCancelled()) {
						break;
					}
			    	double p = i.doubleValue() / numOfBytes;
			    	entropy -= p * (Math.log(p) / Math.log(2));
			    }
			} catch(MemoryAccessException e) {
				printerr("Error occured when calculating entropy at address " + function.getEntryPoint());
			}
			return entropy;
		}
	}
}

final class ControlFlowGraph {
	
	private ControlFlowGraph() {
		// can't create this;
	}
	
	public static GDirectedGraph<CodeBlockVertex, CodeBlockEdge> createControlFlowGraph(Function function, TaskMonitor monitor)
			throws CancelledException {
		GDirectedGraph<CodeBlockVertex, CodeBlockEdge> graph = GraphFactory.createDirectedGraph();
		BasicBlockModel basicBlockModel = new BasicBlockModel(function.getProgram());
		CodeBlockIterator codeBlockIterator
				= basicBlockModel.getCodeBlocksContaining(function.getBody(), monitor);
		
		while (codeBlockIterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			CodeBlock codeBlock = codeBlockIterator.next();
			CodeBlockVertex startVertex = new CodeBlockVertex(codeBlock);
			graph.addVertex(startVertex);
			
			CodeBlockReferenceIterator destinations = startVertex.getCodeBlock().getDestinations(monitor);
				
			while (destinations.hasNext()) {
				if (monitor.isCancelled()) {
					break;
				}
				CodeBlockReference reference = destinations.next();
				FlowType flowType = reference.getFlowType();
					
				if (flowType.isIndirect() || flowType.isCall()) {
					continue;
				}
				CodeBlockVertex destVertex = new CodeBlockVertex(reference.getDestinationBlock());
				graph.addEdge(new CodeBlockEdge(startVertex, destVertex));
			}
		}
		return graph;
	}

}
