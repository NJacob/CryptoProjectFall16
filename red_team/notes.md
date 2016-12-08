## Problems 

### Owen

* Small logic bug when reading `voters.txt`: a trailing newline counts as a valid voter name, so the first person who notices this gets an extra vote

* Timing attack on their client
    - If your first vote is a `1` then it will realize you vote `0` for all other candidates. 
    - If you can monitor the time between the client sending this prompt and getting its answer you can guess at whether the voter voted for the first candidate

* If you vote 0 for the first candidate, you can vote 1 for any number of remaining candidates. This is only safe if there are no more than 2 candidates, but their client allows for an arbitrary number of them. 

* ZKP
    - No randomness is used
    - Only run once with a small, hardcoded constant; chance of guessing is `A^(-t)`, but `t=1` and `A=1`. Thus there's a 1 in 1 chance this can be broken. To fix it, they need to increase both `A` and `t`.

* Secret keys are hardcoded and small; if you bruteforce them (which is straightforward), the whole system becomes compromised (more about that below)

### Nevin

* No random variables are used and the primes used to generate the keys are very small. 
Made a slight modification-> prints out table of encrypted votes just before it counts them. You can see that votes of 1 are always 18L and votes of 0 are always 20448L.
Added a bruteforce method to find the secret key by bruteforcing it two different ways (first simply factors n then calculates lambda and u, second tries every possible lambda and u) and to decrypt the table of encrypted votes with the key that each method finds.
Also made a test to see if ZKP can fail, since their ZKP does all of the work in BB, with the voter never having to do or prove anything throughout the process.

* You can vote 0 for every candidate. Every voter can do this, and the election will still end with 0 valid votes.

* If this was a real system and they fixed that bug, an attacker can see which candidate each voter voted for by counting how many votes they sent (since they vote in a set order and stop once they vote 1). For now we can easily tell if someone voted 1 for the first candidate since they'll only vote once.

* BB encrypts the vote for the voter, meaning it (and anyone who intercepts the message in a real system) can see the plaintext.

