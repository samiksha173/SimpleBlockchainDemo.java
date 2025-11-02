import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;

class Block {
    int index; //store the index(0,1,2)
    String timestamp;//store the time when the block created
    String data;//store the information
    String prevHash;//store the pre block id
    String hash;//display current id

    Block(int index, String data, String prevHash) {
        this.index = index;
        this.timestamp = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date());
        this.data = data;
        this.prevHash = prevHash;
        this.hash = generateHash();
    }

   // SHA is a cryptographic hashing algorithm that converts any input (text, data, file) into a unique 64-character hexadecimal string.
   //index+timestamp+data+prehash
    String generateHash() {
        String input = index + timestamp + data + prevHash;
        return applySha256(input);
    }

    // helper: SHA-256 to hex
    private String applySha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256"); //create the sha hashing object
            byte[] bytes = digest.digest(input.getBytes("UTF-8"));//convert input text in bytes
            StringBuilder hex = new StringBuilder();//it will create the conatiner to build the hexadecimal string
            for (byte b : bytes) { //loop through the every hash
                hex.append(String.format("%02x", b));//it will convert each two byte into hexa
            }
            return hex.toString(); //it will return final hash
        } catch (Exception e) {  //if any exception ,error occure it will handle exception
            throw new RuntimeException(e);
        }
    }
}

class Blockchain {
    ArrayList<Block> chain = new ArrayList<>(); //it will store the block object in order

    // Constructor — create Genesis block
    Blockchain() {
        chain.add(new Block(0, "Genesis Block", "0"));
    }

    // Add block: link to previous block's hash
    void addBlock(String data) {//it takes the data and return nothing
        Block last = chain.get(chain.size() - 1); //find the last block in chain
        Block newBlock = new Block(chain.size(), data, last.hash);//create a new block
        chain.add(newBlock);//append the newly created block in chain
    }

    // Traverse / display chain
    void display() {
        for (Block b : chain) { //for each loop
            System.out.println("Block: " + b.index);
            System.out.println(" Timestamp : " + b.timestamp);
            System.out.println(" Data      : " + b.data);
            System.out.println(" PrevHash  : " + b.prevHash);
            System.out.println(" Hash      : " + b.hash);
            System.out.println("-------------------------------------------------");
        }
    }

    // Verify entire chain integrity
    boolean isChainValid() {
        for (int i = 1; i < chain.size(); i++) {
            Block current = chain.get(i);
            Block previous = chain.get(i - 1);

            // 1) Check current block hash is still valid
            if (!current.hash.equals(current.generateHash())) {
                System.out.println("Invalid hash at block " + current.index);
                return false;
            }

            // 2) Check link to previous block
            if (!current.prevHash.equals(previous.hash)) {
                System.out.println("Broken link at block " + current.index);
                return false;
            }
        }
        return true;
    }

    // Tamper helper — change data of a block (without updating its hash)
    void tamperBlockData(int index, String newData) {
        if (index > 0 && index < chain.size()) { // don't tamper genesis (index 0) here
            chain.get(index).data = newData;
            // DO NOT recalculate hash — this simulates malicious change
        }
    }
}

public class SimpleBlockchainDemo {
    public static void main(String[] args) {
        Blockchain myChain = new Blockchain();

        // Adding blocks
        myChain.addBlock("Alice -> Bob (50 coins)");
        myChain.addBlock("Bob -> Charlie (20 coins)");
        myChain.addBlock("Charlie -> David (10 coins)");

        // Traverse / display
        System.out.println("=== Blockchain (original) ===");
        myChain.display();

        // Verify
        System.out.println("Chain valid? " + myChain.isChainValid());

        // Tamper with block 1 data
        System.out.println("\n--- Tampering with block 1 data ---");
        myChain.tamperBlockData(1, "Alice -> Bob (5000 coins)"); // attacker changes data

        // Display again after tamper
        System.out.println("\n=== Blockchain (after tamper) ===");
        myChain.display();

        // Verify again (should fail)
        System.out.println("Chain valid? " + myChain.isChainValid());
    }
}
