The project was created in python and requires a predefined list of voters called voters.txt and a predefined list of candidates called candidates.txt (This means that the voters were registered ahead of time). All the crypto variables for the code (p, q, a, b, etc.) are pre defined (A more complete system would randomize these to fit the requirements). Using these variables we create ek the encryption key and dk the decryption key.

In this system each part (Election Board, Bulletin Board, and Counting Authority) are defined as classes and the communication between them is simulated by the output of functions being input into a function of a different class. A more complete voting system would utilize networking but that wasn't required in this implementation

In the Election Board class there are three functions, blindSign to blind sign the votes, decrypt to decypt the encrypted votes and decryptVotes to decypt all the votes given to it and announce the winner.

The counting authority has a countVotes functions adds the encrypted votes together and then sends it to the election board.

Finally the bulletin board class has three functions, encrypt encrypts a message using the ek, ZKB which performs the ZKP given a message, and voting which handles the whole voting system. the voting function checks each voter by having them input their name and checks that with the predefined list. it then gets their votes and outputs the table of votes set up as each voter and their vote for each candidate.

To run the code you create the three classes then call the voting function put the output into the countVotes function and put that output into the decryptVotes funcion.

