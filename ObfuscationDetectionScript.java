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
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.util.CyclomaticComplexity;
import ghidra.util.exception.CancelledException;
import ghidra.util.graph.DirectedGraph;
import ghidra.util.graph.Dominator;
import ghidra.util.graph.Edge;
import ghidra.util.graph.Vertex;
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
				analyzeAllFunctions();
				dataSet.sortAndPrint();
				Boolean exportData = askYesNo("Choose", "Do you want to export results in csv format?");
				if(exportData) {
					File outputFolder = askDirectory("Select a folder to save results", "Choose");
					exportToCsvFile(outputFolder);
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
			for(int i = 0; i < 10; i++) {
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
			ControlFlowGraph controlFlowGraph =  new ControlFlowGraph(function, monitor);
			Dominator dominator = new Dominator(controlFlowGraph);
			DirectedGraph dominatorTree = dominator.setDominance();
			Vertex[] nodes = controlFlowGraph.getVertexArray();
			Boolean hasBackEdge;
			Double score = 0.0;
			
			for(int i = 0; i< nodes.length; i++) {
				if(monitor.isCancelled()) {
					break;
				}
				// getDescendants returns nodes[i] as descendant of itself
				Set<Vertex> dominatedBlocks = dominatorTree.getDescendants(nodes[i]);
				Iterator<Vertex> blocksIterator = dominatedBlocks.iterator();
				while(blocksIterator.hasNext()) {
					if(monitor.isCancelled()) {
						break;
					}
					Vertex dominatedBlock = blocksIterator.next();
					hasBackEdge = controlFlowGraph.areRelatedAs(dominatedBlock, nodes[i]);
					if(!hasBackEdge) {
						continue;
					}
					score = Math.max(score, (double)dominatedBlocks.size() / nodes.length);
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

class ControlFlowGraph extends DirectedGraph{
	private Function function;
	private TaskMonitor monitor;

	// makes sure to not insert multiple times the same block in graph
	// when that block is assigned to a different object Vertex.
	public ControlFlowGraph(Function function, TaskMonitor monitor) throws CancelledException {
		this.function = function;
		this.monitor = monitor;
		createControlFlowGraph();
	}
	
	private Vertex properVertex(CodeBlock codeBlock) {
		Vertex[] vertices = getVerticesHavingReferent(codeBlock);
		if(vertices.length == 0) {
			return new Vertex(codeBlock);
		}
		return vertices[0];
	}

	private void createControlFlowGraph()
			throws CancelledException {
		BasicBlockModel basicBlockModel = new BasicBlockModel(function.getProgram());
		CodeBlockIterator codeBlockIterator
				= basicBlockModel.getCodeBlocksContaining(function.getBody(), monitor);

		while (codeBlockIterator.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}

			CodeBlock codeBlock = codeBlockIterator.next();
			Vertex vertexFrom = properVertex(codeBlock);

			add(vertexFrom);
 
			CodeBlockReferenceIterator destinations = codeBlock.getDestinations(monitor);
			while (destinations.hasNext()) {
				if (monitor.isCancelled()) {
					break;
				}

				CodeBlockReference reference = destinations.next();
				FlowType flowType = reference.getFlowType();
				if (flowType.isIndirect() || flowType.isCall()) {
					continue;
				}

				Vertex vertexTo = properVertex(reference.getDestinationBlock());
				Edge edge = new Edge(vertexFrom, vertexTo);
				add(edge);
			}
		}
	}
}
