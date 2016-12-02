# CryptoProjectFall16

Group Members:
Amartya Chakraborty
Nevin Jacob
Owen Stenson

Requirements:
Python 2.7
gmpy2 and Tkinter python packages

How to run:
python election.py candidates.txt <numvotes>
where numvotes is how many votes you want the system to count before it ends the voting process and returns the election results.
Any text file with one candidate name per line can be used instead of candidates.txt

After starting the program, simply provide a unique name for each of the numvotes voters, select their vote, and press the 'Vote' button. 

Assumptions:
Every voter that registers will eventually send a valid vote.
Voters not using the GUI (which should only be possible if the entire election is being run on another client) will pay attention to the error messages if their vote fails and respond accordingly to complete their vote.

