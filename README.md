This is a file-based cryptocurrency I created called Colbybucks, which uses RSA encryption and file-based wallets and blockchain. Users are able to create their own encrypted wallets
and send/receive Colbybucks. There is also built in economic controls, such as mining difficulty and limited amount of currency available for transactions.

# Usages
 - java CMoney name
   - Prints name of the cryptocurrency, Colbybucks
 - java CMoney genesis
   - Creates the genesis block in the blockchain, writing to block_0.txt
 - java CMoney generate alice.wallet.txt
   - Creates a RSA public/private key set in a wallet file
 - java CMoney address alice.wallet.txt
   - Print the tag of the public key of a particular wallet
 - java CMoney fund <tagA> 999 01-alice-funding.txt
   - Credit a particular wallet using Colbybucks from a central administrative wallet
   - This allows us to control the amount of Colbybucks available for exchange
   - Save the transaction statement in the mentioned file
 - java CMoney transfer alice.wallet.txt <tagB> 999 03-alice-to-bob.txt
   - Pay out a number of Colbybucks to the wallet with the public key specified by tagB
   - Write the transaction statement in the mentioned file
 - java CMoney balance <tagA>
   - Check the current balance of a particular wallet using its public key tag
   - Reference transactions currently in the blockchain and in the mempool for accuracy
 - java CMoney verify bob.wallet.txt 04-bob-to-alice.txt
   - Verify if the transaction specified by the transaction file is indeed valid, in which case add it as a transaction line to the mempool
   - Check balance and signature
 - java CMoney mine 2
   - Create a new block in the blockchain, emptying the mempool of lines
   - Compute a nonce to ensure the hash is below a certain value
   - We specify the difficulty, which is the leading number of zeroes to have in the hash, ensuring some difficulty of finding the nonce
 - java CMoney validate
   - Go through each block in the blockhain and validate all blocks by checking if the hash written in each file is the hash for the previous block
   - Check if a genesis block exists
