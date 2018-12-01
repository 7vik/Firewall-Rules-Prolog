# CS F214 - Firewall Rules encoded in Prolog
## Objective
 * To apply a set of pre-defined rules on internet packet headers, and
 * To accept, reject, or drop (silently) each packet with a given precedence.
 * Other details are in [Problem Statement](ProblemStatement.md)

## Description:
 * Internet packets arrive comprising three parts: a header, the payload (content), and the trailer. A firewall acts as a line of defense for our system, accepting and rejecting data packets based on their headers, using pre-defined rules.
 * We have encoded basic firewall rules in Prolog, and the precedence decreases from reject to drop to accept.  
 * The ready-to-work file, 'Firewall.pl' contains both the database and rule engine, and can be loaded and used directly, while
 * The folder "Firewall Codes" contains two separate files for engine and database, which can be used to test / modify the code on the merits of maintenance and reusability.  

## Input Format
 * Header packets are input as a list to the Prolog term 'filter'.
 * Sample inputs are available in the file [Sample Inputs](sample_inputs.txt).

## Usage:
1. Load the file Firewall.pl using SWI Prolog.
```bash
swipl Firewall.pl
```
2. Use the term 'filter' to filter any packet. Load the sample inputs from the file.
```prolog
?- filter([a,0x86dd,576,'192.26.26.254','TCP',17267,21834,6]). 
```
3. The program will tell if the packet is accepted or rejected, or will silently drop it. Press '.' to proceed with another packet.

4. If the database and engine need to be separately loaded, use the following bash command:
```bash
swipl ./database/engine.pl ./database/database.pl
```
5. Exit SWI Prolog using-
```prolog
halt().
```

### Authors:
Satvik Golechha 2017A7PS0117P<br>
Bharat Bhargava 2017A7PS0025P
