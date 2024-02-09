import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;

public class CMoney {
    static String cryptoName = "Colbybucks";
    static String fundSource = "Colby";
    public CMoney(){
        //blockchain = new ArrayList();
    }

    public static void buildMempool(){
        File mempool = new File("mempool.txt");

        try {
            mempool.createNewFile();
        } catch (IOException e) {
            System.out.println("error building mempool");
            e.printStackTrace();
        }
    }

    public static void clearMempool(){
        File mempool = new File("mempool.txt");
        if(mempool.exists()) mempool.delete();
        buildMempool();
    }
    public static int getBlockchainSize(){
        int blockchainSize = 1;
        String lastBlock = "block_1.txt";
        File lastBlockFile = new File(lastBlock);

        while (lastBlockFile.exists()) {
            blockchainSize++;
            lastBlock = "block_" + blockchainSize + ".txt";
            lastBlockFile = new File(lastBlock);
        }
        return blockchainSize;
    }

    public static String[] getBlockchain(){
        int blockchainSize = getBlockchainSize();
        String[] blockchain = new String[blockchainSize];
        for(int i = 0; i < blockchainSize; i++){
            blockchain[i] = "block_" + i + ".txt";
        }
        return blockchain;
    }

    public static void createGenesis(){
        File file = new File("block_0.txt");

        try {
            FileWriter writer = new FileWriter(file);
            writer.write("Hello grader. This is here solely so that this file is not empty. Are you happy?");
            writer.close();
            System.out.println("Genesis block created in 'block_0.txt'");

        } catch (IOException e) {
            System.out.println("Error writing genesis block");
            e.printStackTrace();
        }
    }

    // this converts an array of bytes into a hexadecimal number in
    // text format
    static String getHexString(byte[] b) {
        String result = "";
        for (int i = 0; i < b.length; i++) {
            int val = b[i];
            if ( val < 0 )
                val += 256;
            if ( val <= 0xf )
                result += "0";
            result += Integer.toString(val, 16);
        }
        return result;
    }

    // This will write the public/private key pair to a file in text
    // format.  It is adapted from the code from
    // https://snipplr.com/view/18368/saveload--private-and-public-key-tofrom-a-file/
    static void SaveKeyPair(String filename, KeyPair keyPair) throws Exception {
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(keyPair.getPublic().getEncoded());
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
        PrintWriter fout = new PrintWriter(new FileOutputStream(filename));
        fout.println(getHexString(x509EncodedKeySpec.getEncoded()));
        fout.println(getHexString(pkcs8EncodedKeySpec.getEncoded()));
        fout.close();
    }

    public static String getTag(PublicKey publicKey){
        MessageDigest digest = null;
        try {
            digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(publicKey.getEncoded());
            String tag = getHexString(hash).substring(0, 17);
            return tag;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static KeyPair generateKeyPair(){
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024); // you can specify the key size here
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return keyPair;
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void generateWallet(String fileName, boolean printResponse) {
        try {
            File file = new File(fileName);
            KeyPair keyPair = generateKeyPair();
            SaveKeyPair(fileName, keyPair);
            if(printResponse){
                System.out.println("New wallet generated in '" + fileName + "' with tag " + getTag(keyPair.getPublic()));
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // this converts a hexadecimal number in text format into an array
    // of bytes
    static byte[] getByteArray(String hexstring) {
        byte[] ret = new byte[hexstring.length()/2];
        for (int i = 0; i < hexstring.length(); i += 2) {
            String hex = hexstring.substring(i,i+2);
            if ( hex.equals("") )
                continue;
            ret[i/2] = (byte) Integer.parseInt(hex,16);
        }
        return ret;
    }

    static KeyPair LoadKeyPair(String filename) {
        try {
            // Read wallet
            Scanner sin = null;
            sin = new Scanner(new File(filename));
            byte[] encodedPublicKey = getByteArray(sin.next());
            byte[] encodedPrivateKey = getByteArray(sin.next());
            sin.close();

            // Generate KeyPair.
            KeyFactory keyFactory = null;
            keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
            PublicKey publicKey = null;
            publicKey = keyFactory.generatePublic(publicKeySpec);
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encodedPrivateKey);
            PrivateKey privateKey = null;
            privateKey = keyFactory.generatePrivate(privateKeySpec);
            return new KeyPair(publicKey, privateKey);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static void printWalletTag(String fileName){
        try {
            PublicKey publicKey = LoadKeyPair(fileName).getPublic();
            System.out.println(getTag(publicKey));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public static String getSignature(String plainText, PrivateKey privateKey){
        Signature privateSignature = null;
        try {
            privateSignature = Signature.getInstance("SHA256withRSA");
            privateSignature.initSign(privateKey);
            privateSignature.update(plainText.getBytes(UTF_8));
            byte[] signature = privateSignature.sign();
            return Base64.getEncoder().encodeToString(signature);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static void handleTransaction(String source, String destination, int amount, String fileName){
        File file = new File(fileName);

        try {
            FileWriter writer = new FileWriter(file);
            String fromLine = "From: ";
            String toLine = "To: " + destination;
            String amountLine = "Amount: " + amount;
            Date transactionDate = new Date();
            String dateString = transactionDate.toString();
            String dateLine = "Date: " + dateString;

            KeyPair senderKeyPair = LoadKeyPair(source);
            PrivateKey senderPrivateKey = senderKeyPair.getPrivate();
            PublicKey senderPublicKey = senderKeyPair.getPublic();
            String senderTag = getTag(senderPublicKey);
            if(source.equals("Colby.wallet.txt")){
                fromLine += fundSource;
            }
            else {
                fromLine += senderTag;
            }
            String signThisText = fromLine + toLine + amountLine + dateLine;
            String signatureLine = getSignature(signThisText, senderPrivateKey);

            if(source.equals(fundSource)){
                System.out.println("Funded wallet " + destination + " with " + amount + " " + cryptoName + " on " + dateString);
            }
            else{
                System.out.println("Transferred " + amount + " from " + source + " to " + destination + " and the statement to " + fileName + " on " + dateString);
            }

            writer.write(fromLine + "\n");
            writer.write(toLine + "\n");
            writer.write(amountLine + "\n");
            writer.write(dateLine + "\n");
            writer.write("\n" + signatureLine + "\n");
            writer.close();

        } catch (IOException e) {
            System.out.println("Error writing transaction block");
            e.printStackTrace();
        }
    }
    public static int getFileBalance(String tag, String fileName){
        //taga/Colby transferred 100 to tagb on Tue ...
        int balance = 0;

        File file = new File(fileName);
        try {
            Scanner scanner = new Scanner(file);
            while(scanner.hasNextLine()){
                String transactionLine = scanner.nextLine();
                String[] splitLine = transactionLine.split(" ");
                if(splitLine.length >= 4) {
                    if (splitLine[4].equals(tag)) {
                        //tag is the recipient
                        balance += Integer.valueOf(splitLine[2]);
                    } else if (splitLine[0].equals(tag)) {
                        //tag is the sender
                        balance -= Integer.valueOf(splitLine[2]);
                    }
                }
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }
        return balance;
    }

    public static int getBalance(String tag, boolean print){
        int totalBalance = 0;
        String[] blockchain = getBlockchain();

        //check blocks
        for(String block : blockchain){
            totalBalance += getFileBalance(tag, block);
        }
        //check mempool
        totalBalance += getFileBalance(tag, "mempool.txt");
        if(print) System.out.println(totalBalance);
        return totalBalance;
    }

    public static boolean verify(String plainText, String signature, PublicKey publicKey){
        try {
            Signature publicSignature = Signature.getInstance("SHA256withRSA");
            publicSignature.initVerify(publicKey);
            publicSignature.update(plainText.getBytes(UTF_8));
            byte[] signatureBytes = Base64.getDecoder().decode(signature);
            return publicSignature.verify(signatureBytes);

        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    public static void writeToMempool(String str){
        try {
            FileWriter writer = new FileWriter("mempool.txt", true);
            writer.write(str + "\n");
            writer.close();
        } catch (IOException e) {
            System.out.println("Error writing to mempool");
            e.printStackTrace();
        }
    }

    public static void handleVerify(String wallet, String transaction){
        KeyPair walletKeyPair = LoadKeyPair(wallet);
        PublicKey walletPublicKey = walletKeyPair.getPublic();
        try {
            File transactionFile = new File(transaction);
            Scanner scanner = new Scanner(transactionFile);
            String fromLine = scanner.nextLine();
            String toLine = scanner.nextLine();
            String amountLine = scanner.nextLine();
            String dateLine = scanner.nextLine();
            String verifyThisText = fromLine + toLine + amountLine + dateLine;

            scanner.nextLine(); //throw away paragraph buffer
            String signature = scanner.nextLine();

            int amount = Integer.valueOf(amountLine.split(" ")[1]);
            String destination = toLine.split(" ")[1];
            String sender = fromLine.split(" ")[1];
            String walletTag = getTag(walletPublicKey);

            boolean signaturesMatch = verify(verifyThisText, signature, walletPublicKey);
            boolean enoughFunds;
            if(sender.equals(fundSource)){
                enoughFunds = true;
                signaturesMatch = true;
                walletTag = fundSource;
            }
            else{
                enoughFunds = getBalance(walletTag, false) >= amount;
            }
            if(signaturesMatch && enoughFunds){
                //taga/Colby transferred 100 to tagb on Tue ...
                writeToMempool(walletTag + " transferred " + amount + " to " + destination + " on " + new Date().toString());
                System.out.println("The transaction in file '" + transaction + "' with wallet '" + wallet + "' is valid, and was written to the mempool");
            }
            else{
                System.out.println("Error, unverified. Either you have insufficient funds and need to verify a funding transaction or you have mismatching signatures.");
            }
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String getHashOfFile(String filename){
        try {
            byte[] filebytes = Files.readAllBytes(Paths.get(filename));
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHash = digest.digest(filebytes);
            return getHexString(encodedHash);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String findNonce(String fileContent, int difficulty){
        try {
            while(true){
                String randNonce = "";
                for(int i = 0; i<4; i++){
                    Random random = new Random();
                    int randomNumber = random.nextInt(10) + 48; //48 = ascii for 0, 57 = ascii for 9
                    char randomChar = (char) randomNumber;
                    randNonce+=randomChar;
                }
                String contentPlusNonce = fileContent + randNonce;
                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] encodedHash = digest.digest(contentPlusNonce.getBytes());
                String checkString = "";
                for(int i = 0; i<difficulty; i++){
                    checkString += "0";
                }
                if(getHexString(encodedHash).substring(0, difficulty).equals(checkString)){
                    return randNonce;
                }
            }
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void handleMine(int difficulty){
        int blockNumber = getBlockchainSize();
        int prev = blockNumber - 1;
        String prevBlock = "block_" + prev + ".txt";
        String newBlock = "block_" + blockNumber + ".txt";
        String hash = getHashOfFile(prevBlock);
        String fileContent = "";
        try {
            FileWriter writer = new FileWriter(newBlock, true);
            File mempool = new File("mempool.txt");
            writer.write(hash + "\n");
            fileContent += hash + "\n";
            writer.write("\n");
            fileContent += "\n";
            Scanner mempoolScanner = new Scanner(mempool);
            while(mempoolScanner.hasNextLine()){
                String transactionLine = mempoolScanner.nextLine();
                writer.write(transactionLine + "\n");
                fileContent += transactionLine + "\n";
            }
            writer.write("\n");
            writer.write("nonce: ");
            fileContent += "\n";
            fileContent += "nonce: ";

            String nonce = findNonce(fileContent, difficulty);
            writer.write(nonce);
            writer.close();

            clearMempool();
            System.out.println("Mempool transactions moved to " + newBlock + " and mined with difficulty " + difficulty + " and nonce " + nonce);
        } catch (IOException e) {
            System.out.println("Error writing to block");
            e.printStackTrace();
        }

    }

    public static boolean handleValidate() {
        int blockchainSize = getBlockchainSize();

        for (int i = 1; i < blockchainSize; i++) {
            int prev = i - 1;
            String prevBlock = "block_" + prev + ".txt";
            String currBlock = "block_" + i + ".txt";
            File currBlockFile = new File(currBlock);

            String prevBlockHash = getHashOfFile(prevBlock);
            Scanner currBlockScanner = null;
            try {
                currBlockScanner = new Scanner(currBlockFile);
            } catch (FileNotFoundException e) {
                throw new RuntimeException(e);
            }
            String hashLine = currBlockScanner.nextLine();
            if (!hashLine.equals(prevBlockHash)) {
                System.out.println("False");
                return false;
            }
        }
        System.out.println("True");
        return true;
    }

    public static void main(String args[]) {
        buildMempool();

        if (args[0].equals("name")) {
            System.out.println(cryptoName);
        } else if (args[0].equals("genesis")) {
            createGenesis();
        } else if (args[0].equals("generate")) {
            generateWallet(args[1], true);
        } else if (args[0].equals("address")) {
            printWalletTag(args[1]);
        } else if (args[0].equals("fund")) {
            generateWallet(fundSource + ".wallet.txt", false);
            handleTransaction(fundSource + ".wallet.txt", args[1], Integer.valueOf(args[2]), args[3]);
        } else if (args[0].equals("transfer")) {
            handleTransaction(args[1], args[2], Integer.valueOf(args[3]), args[4]);
        } else if(args[0].equals("balance")) {
            getBalance(args[1], true);
        } else if(args[0].equals("verify")) {
            handleVerify(args[1], args[2]);
        } else if(args[0].equals("mine")){
            handleMine(Integer.valueOf(args[1]));
        } else if(args[0].equals("validate")){
            handleValidate();
        }
        //erase mempool after mine
        //update mine transaction line

    }
}
