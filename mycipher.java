/**
 * 
 */

import java.io.*;
import java.util.ArrayList;

/**
 * @author Dan Ohlin and Stefan Moore
 * Class: TCN 5080 Secure Telecom Trans
 * Project 1
 * September 6, 2014
 */


public class mycipher {

	/**Input Format:
	*The program should take a command in the following format.
	*(java) mycipher -m mode -k initial_key -i initial_vector -p plaintext_file -c ciphertext_file
	*mode: can be only encrypt or decrypt
	*initial_key: 10-bit initial key
	*initial_vector: 8-bit initial vector
	*plaintext_file: a binary (not text) file to store the plaintext
	*ciphertext_file: a binary (not text) file to store the ciphertext
	*
	*Sample:java mycipher -m encrypt -k 0111111101 -i 10101010 -p f1 -c f3
	*java mycipher -m decrypt -k 0101010101 -i 00000000 -p f4 -c f2
	 * @param args
	 */

	private static String fileToRead = " ";
	private static String fileToWrite = " ";
	private static int[] integersRead;
	private static int[] integerstoWrite;
	private static int numberOfBlocks = 0;
	private static int intIV = 0;
	private static int tempCbc = 0;
	private static int[] tempCbcArray = new int[8];
	private static String mode = "", key = "", iv = "", plaintextFile = "", ciphertextFile = "", plaintext = "", plaintextByte = "", ciphertext = "", ciphertextByte = "", displayKey1 = "", displayKey2 = "";
	private static int[] keyArray = new int[10];
	private static int[][] subkeys = new int[2][8];
	private static int[] k1 = new int[8];
	private static int[] k2 = new int[8];
	private static int[] plaintextPrintingArray = new int[8];

	
	public static void main(String[] args) throws IOException {
		
		// read arguments
		if (args.length > 8) {
			for (int i = 0; i < args.length; i++) {
				switch (args[i]) {
				case "-m":
					mode = args[i + 1];
					break;
				case "-k":
					key = args[i + 1];
					break;
				case "-i":
					iv = args[i + 1];
					intIV = StringToInterger(iv);
					break;
				case "-p":
					plaintextFile = args[i + 1];
					break;
				case "-c":
					ciphertextFile = args[i + 1];
					break;					
				}
			}
		}
		
		// Decide Encrypt/Decrypt. Set Read From and Write To files.
		if (mode.compareToIgnoreCase("encrypt") == 0) {
			fileToRead = plaintextFile;
			fileToWrite = ciphertextFile;
		}
		else {
			fileToRead = ciphertextFile;
			fileToWrite = plaintextFile;
		}
		
		//Check if file exists and read it
		File checkFile = new File(fileToRead);
		if (checkFile.exists()) {
			integersRead = ReadMessageBlock(fileToRead);
			numberOfBlocks = integersRead.length;
			integerstoWrite = new int[numberOfBlocks];
		} else {
			System.out.println("Plaintext file does not exist.");
			System.exit(1);
		}
		
		
		//Generate k1 and k2
		keyArray = IntegerToBinary(StringToInterger(key), 10);
		subkeys = GenerateKey(keyArray);
		for (int i = 0; i < 8; i++){
			k1[i] = subkeys[0][i];
			displayKey1 += subkeys[0][i];
		}
		for (int i = 0; i < 8; i++){
			k2[i] = subkeys[1][i];
			displayKey2 += subkeys[1][i];
		}		
		
		
		//CBC
		if (mode.compareToIgnoreCase("encrypt") == 0) {
			// CBC Encryption
			int xorInput = intIV;
			for (int i = 0; i < numberOfBlocks; i++) {
				
				//Plaintext to print to command line
				plaintextPrintingArray = IntegerToBinary(integersRead[i]);
				for (int j = 0; j < 8; j++){
					plaintext += plaintextPrintingArray[j];
				}
				plaintext += " ";
				
				//CBC XOR
				tempCbc = xorInput ^ integersRead[i];
				tempCbcArray = IntegerToBinary(tempCbc);

				//Call S-DES algorithm
				tempCbcArray = Crypt(tempCbcArray, k1, k2);
				
				//Ciphertext to print to command line
				for (int j = 0; j < 8; j++){
					ciphertext += tempCbcArray[j];
				}
				ciphertext += " ";
				
				tempCbc = BinaryToInterger(tempCbcArray);
				integerstoWrite[i] = tempCbc;
				xorInput = tempCbc;

			}

		} else {

			for (int i = numberOfBlocks - 1; i >= 0; i--){
				// CBC Decryption				
				tempCbcArray = IntegerToBinary(integersRead[i]);

				//Ciphertext to print to command line
				for (int j = 0; j < 8; j++){
					ciphertextByte += tempCbcArray[j];
				}
				ciphertext = ciphertextByte + " " + ciphertext;
				ciphertextByte = "";

				//Call S-DES algorithm - keys are switched as we are decrypting.
				tempCbcArray = Crypt(tempCbcArray, k2, k1); // 
				tempCbc = BinaryToInterger(tempCbcArray);
				
				//CBC XOR
				if (i > 0) {
					integerstoWrite[i] = tempCbc ^ integersRead[i-1];
				} else {
					integerstoWrite[i] = tempCbc ^ intIV;
				}
				
				//Plaintext to print to command line				
				plaintextPrintingArray = IntegerToBinary(integerstoWrite[i]);
				for (int j = 0; j < 8; j++){
					plaintextByte += plaintextPrintingArray[j];
				}
				plaintext = plaintextByte + " " + plaintext;
				plaintextByte = "";
				
			}
		}
		
		//Write results to file
		WriteMessageBlock(integerstoWrite, fileToWrite);
		
		//Print results to screen when done
		System.out.println("k1=" + displayKey1);
		System.out.println("k2=" + displayKey2);
		if (mode.compareToIgnoreCase("encrypt") == 0){
			System.out.println("plaintext=" + plaintext);
			System.out.println("ciphertext=" + ciphertext);
		} else {
			System.out.println("ciphertext=" + ciphertext);
			System.out.println("plaintext=" + plaintext);
		}
		
	}
	
	//*********Methods called by main**************
	
	//Read file
	private static int[] ReadMessageBlock(String fileToRead) throws IOException {
		
		int block = 0;
		ArrayList<Integer> m = new ArrayList<Integer>();
		
		FileInputStream input = new FileInputStream(fileToRead);
		
		while ((block = input.read()) != -1) {
			m.add(block);
		}
		input.close();

		int[] returnMessageArray = new int[m.size()];
		for (int i = 0; i < m.size(); i++) {
			returnMessageArray[i] = m.get(i).intValue();
		}
		return returnMessageArray;
	}
	
	//Write file
	private static int WriteMessageBlock(int[] intergersToWrite, String fileToWrite) throws IOException {
		FileOutputStream output = new FileOutputStream(fileToWrite);
		
		for (int integerToWrite: intergersToWrite) {
			output.write(integerToWrite);
		}
		output.close();
		return 0;
	}

	//Convert from integer array to binary
	private static int[] IntegerToBinary(int intToConvert) {
		int[] blockBits = new int[8];
		
		String bitString = (Integer.toBinaryString(intToConvert));
		
		int leadingZeros = 8 - bitString.length();
		for (int i = 0; i < leadingZeros; i++) {
			blockBits[i] = 0;
		}
		for (int i = 0; i < bitString.length(); i++) {
 			blockBits[i + leadingZeros] = Integer.parseUnsignedInt(bitString.substring(i, i+1));
		}
		
		return blockBits;
	}
	
	//Convert from integer array to binary (overloaded). Len parameter is the length of the array.
	private static int[] IntegerToBinary(int intToConvert, int len) {
		int[] blockBits = new int[len];
		
		String bitString = (Integer.toBinaryString(intToConvert));
		
		int leadingZeros = len - bitString.length();
		for (int i = 0; i < leadingZeros; i++) {
			blockBits[i] = 0;
		}
		for (int i = 0; i < bitString.length(); i++) {
 			blockBits[i + leadingZeros] = Integer.parseUnsignedInt(bitString.substring(i, i+1));
		}
		
		return blockBits;
	}
	
	//Convert from binary to integer array
	private static int BinaryToInterger(int[] blockBits){

		int returnInterger = 0;
		int tempInt = 0;
		for (int i = 0; i < 8; i++) {
			if (blockBits[i] == 1) {
				tempInt = (int)Math.pow(2, (7-i));
				returnInterger += tempInt;
			}
		}
		return returnInterger;
	}
	
	//Convert from binary to integer array (overloaded). Len parameter is the length of the array.
	private static int BinaryToInterger(int[] blockBits, int len){

		int returnInterger = 0;
		int tempInt = 0;
		for (int i = 0; i < len; i++) {
			if (blockBits[i] == 1) {
				tempInt = (int)Math.pow(2, ((len-1)-i));
				returnInterger += tempInt;
			}
		}
		return returnInterger;
	}

	//Convert from String to integer
	private static int StringToInterger(String stringBits){

		int returnInterger = Integer.parseInt(stringBits, 2);
		
		return returnInterger;
	}

	
	//********S-DES Crypt********
	
	//Crypt() method - used for both encryption and decryption
	private static int[] Crypt(int[] block, int[] k1, int[] k2) {

		int[] L = new int[4];
		int[] R = new int[4];
		int[] swapL = new int[4];
		
		//Initial permutation
		block = IP(block);
		
		//Split left and right
		System.arraycopy(block, 0, L, 0, 4);
		System.arraycopy(block, 4, R, 0, 4);
		
		//Call FunctionFK
		FunctionFK(L, R, k1);
		
		//Switch
		swapL = L;
		L = R;
		R = swapL;

		//Call FunctionFK
		FunctionFK(L, R, k2);
		
		//Combine left and right
		System.arraycopy(L, 0, block, 0, 4);
		System.arraycopy(R, 0, block, 4, 4);

		//Inverse IP
		block = invIP(block);
	
		return block;
	}
	
	
	//********S-DES Crypt() sub operation methods********
	
	// Permutation of 8-bit input to IP
	private static int[] IP(int[] text)
	{
		int[] ip = new int[8];
		int[] ipPerm = {2, 6, 3, 1, 4, 8, 5, 7};
		
		for (int i = 0; i < ipPerm.length; i++)
			ip[i]=text[ipPerm[i]-1];

		return ip;
	}

	// Inverse Permutation of 8-bit IP
	private static int[] invIP(int[] text)
	{
		int[] ip = new int[8];
		int[] invPerm = {4, 1, 3, 5, 7, 2, 8, 6};
		
		for (int i = 0; i < invPerm.length; i++)
			ip[i]=text[invPerm[i]-1];

		return ip;
	}

	//FunctionFK
	private static void FunctionFK(int[] L, int[] R, int[] key) {
		
		int[] cryptR = new int[4];
		System.arraycopy(R, 0, cryptR, 0, 4);
		
		//Call FunctionF
		cryptR = FunctionF(cryptR, key);
		
		// XOR with Left side
		for (int i = 0; i < 4; i++) {
			L[i] = L[i] ^ cryptR[i];
		}
	}

	//FunctionF
	private static int[] FunctionF(int[] cryptR, int[] key) {
		
		int[] cryptR8 = new int[8];
		int[] Left = new int[4];
		int[] Right = new int[4];
		int[] sbox0Result = new int[2];
		int[] sbox1Result = new int[2];
		int[] p4 = new int[4];

		//Expansion/Permutation
		cryptR8 = EP(cryptR);
		
		//XOR with key
		for (int i = 0; i < 8; i++){
			cryptR8[i] = cryptR8[i] ^ key[i];
		}
		
		//S-BOXes
		System.arraycopy(cryptR8, 0, Left, 0, 4);
		System.arraycopy(cryptR8, 4, Right, 0, 4);
		sbox0Result = SBox(Left, 0);
		sbox1Result = SBox(Right, 1);
	
		//P4 permutation
		p4[0] =  sbox0Result[1];
		p4[1] =  sbox1Result[1];
		p4[2] =  sbox1Result[0];
		p4[3] =  sbox0Result[0];
		
		return p4;
	}
	
	// Expansion/Permutation of 4-bit input to EP
	private static int[] EP(int[] text)
	{
		int[] ep = new int[8];
		int[] epPerm = {4, 1, 2, 3, 2, 3, 4, 1};
		
		for (int i = 0; i < epPerm.length; i++)
			ep[i]=text[epPerm[i]-1];
		return ep;
	}

	//S-Boxes
	private static int[] SBox(int[] input, int box) {

		int[][] s0 = {
				{1, 0, 3, 2},
				{3, 2, 1, 0},
				{0, 2, 1, 3},
				{3, 1, 3, 2}
		};
		
		int[][] s1 = {
				{0, 1, 2, 3},
				{2, 0, 1, 3},
				{3, 0, 1, 0},
				{2, 1, 0, 3}
		};
		
		int output = 0;
		int[] outputArray = new int[2];
		int row = 0;
		int column = 0;
		int[] rowArray = new int[2];
		int[] columnArray = new int[2];
		
		rowArray[0] = input[0];
		rowArray[1] = input[3];
		columnArray[0] = input[1];
		columnArray[1] = input[2];	
		
		row = BinaryToInterger(rowArray, 2);
		column = BinaryToInterger(columnArray, 2);
		
		if (box == 0) {
			output = s0[row][column];			
		} else {
			output = s1[row][column];
		}

		outputArray = IntegerToBinary(output, 2);
		
		return outputArray;
		
	}

	
	/*	********************************************************************************** 
	Function:	GenerateKey
	Purpose:	Generates 8-bit subkeys from 10-bit key as specified in SDES
	Returns:	2-D array with subkey1 in array1 and subkey2 in array2
 	********************************************************************************** */
	
	private static int[][] GenerateKey(int[] key)
	{
		int[] permutation1 = {3, 5, 2, 7, 4, 10, 1, 9, 8, 6};	// first permutation order
		int[] p10 = new int[10];								// temp arrays to permute 10-bit key
		int[] p10LFT = new int[5];
		int[] p10RHT = new int[5];		
		int[] LS_BEG = new int[5];								// temp arrays to perform left shifts		
		int[] LS_END = new int[5]; 		
		int[] LS1 = new int[10];
		int[] LS2 = new int[10];
		int[] permutation2 = {6, 3, 7, 4, 8, 5, 10, 9};			// second permutation order 
		int[] p8_1 = new int[8];								// array used to permute and reduce shifted 10 bits to 8
		int[] p8_2 = new int[8];								// array used to permute and reduce shifted 10 bits to 8

	
		//Permute 10-bit key to p10
		for(int i = 0; i < permutation1.length; i++)
			p10[i]=key[permutation1[i]-1];
		
		 //Split p10 into 5-bit arrays for shifting
		for (int i=0; i < p10.length/2; i++)
		{
			p10LFT[i] = p10[i];
			p10RHT[i] = p10[i+5];
		}
		
		//Perform 1-bit Left Shift on p10LFT
		LS_BEG[0] = p10LFT[1];
		LS_BEG[1] = p10LFT[2];
		LS_BEG[2] = p10LFT[3];
		LS_BEG[3] = p10LFT[4];
		LS_BEG[4] = p10LFT[0];
		
		//Perform 1-bit Left Shift on p10RHT
		LS_END[0] = p10RHT[1];
		LS_END[1] = p10RHT[2];
		LS_END[2] = p10RHT[3];
		LS_END[3] = p10RHT[4];
		LS_END[4] = p10RHT[0];
		
		//Populate LS1[] with LS_BEG and LS_END
		System.arraycopy(LS_BEG, 0, LS1, 0, LS_BEG.length);
		System.arraycopy(LS_END, 0, LS1, LS_BEG.length, LS_END.length);
		
		//Perform cumulative 3-bit Left Shift on p10LFT (LS-1 and LS-2)
		LS_BEG[0] = p10LFT[3];
		LS_BEG[1] = p10LFT[4];
		LS_BEG[2] = p10LFT[0];
		LS_BEG[3] = p10LFT[1];
		LS_BEG[4] = p10LFT[2];
		
		//Perform cumulative 3-bit Left Shift on p10RHT (LS-1 and LS-2)
		LS_END[0] = p10RHT[3];
		LS_END[1] = p10RHT[4];
		LS_END[2] = p10RHT[0];
		LS_END[3] = p10RHT[1];
		LS_END[4] = p10RHT[2];

		//Populate LS2[] with LS_BEG and LS_END
		System.arraycopy(LS_BEG, 0, LS2, 0, LS_BEG.length);
		System.arraycopy(LS_END, 0, LS2, LS_BEG.length, LS_END.length);
		
		//Permute 10-bit LS1 and LS2 to 8-bit p8
		for(int i = 0; i < permutation2.length; i++) 
		{
			p8_1[i]=LS1[permutation2[i]-1];
			p8_2[i]=LS2[permutation2[i]-1];
		}

		//Copy subkeys to 2D array in order to output both subkeys to caller
		int[][] subkeys = new int[2][8];
		for (int n = 0; n < 8; n++) {
			subkeys[0][n] = p8_1[n];
		}
		for (int n = 0; n < 8; n++) {
			subkeys[1][n] = p8_2[n];
		}
		return subkeys;
	}

}
