%    *************** CS F214 - Firewall Rules on Incoming Packets ***************
% Bharat B - 0025
% Satvik G - 0117


% ***************** Database 1 :: Definition (Grammar) of adapter clauses allowed  *************

adapter(a).
adapter(b).
adapter(c). 


% *************************** End of Database 1 ************************************************





%Comment the following samples after writing databases for each clause.
ethernet(w).
ip(e).
protocol(r).

allow(A,B,C,D) :- adapter(A),ethernet(B),ip(C),protocol(D).

