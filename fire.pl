%    *************** CS F214 - Firewall Rules on Incoming Packets ***************
% Bharat B - 0025
% Satvik G - 0117


% ***************** Database 1 :: Definition (Grammar) of adapter clauses allowed  *************

adapter(a).
adapter(b).
adapter(c).

% ***************** Database 2 :: Grammar of protocols allowed ************
proto('UDP').
proto('TCP').
proto('ICMP').

%***************** Database 3 :: Grammar of ethernets allowed************
ethernet(0x86dd).
ethernet(0x0800).
ethernet(0xf002).
ethernet(0xaa38).


% ***************** Database 4 :: Grammar of ip addresses allowed************
ip('172.24.16.31').
ip('192.26.26.250').
ip('187.24.31.6').
% *************************** End of Databases ******************************

allow([U,W,Y,Z|_]) :- adapter(U),ethernet(W),\+ip(Y),proto(Z). 




