%    *************** CS F214 - Firewall Rules on Incoming Packets ***************
% Bharat B - 0025
% Satvik G - 0117


% ***************** Database 1 :: Definition (Grammar) of adapter clauses allowed  *************
adapter(a).
adapter(d).
adapter(g).

% ***************** Database 2 :: Grammar of protocols allowedi************
proto('UDP').
proto('TCP').
proto('ICMP').

% ***************** Database 3 :: Grammar of ethernet protocols allowed************
ether_proto(0x86dd).
ether_proto(0x0800).
ether_proto(0xf002).
ether_proto(0xaa38).

% ***************** Database 4 :: Grammar of ip addresses to be blocked and the packet to be dropped/rejected ************
ip('172.24.16.31').
ip('192.26.26.250').
ip('187.24.31.6').
ip_drop('172.27.18.213'). %****Drop the packet in this case****%
ip_drop('191.25.22.123'). %****Drop the packet in this case****%

% ***************** Database 5 :: Grammar of tcp source addresses to be blocked and the packet to be rejected ************
proto_src(65530).
proto_src(53789).
proto_src(58779).

% ***************** Database 6 :: Grammar of VLAN identifiers to be blocked and the packet to be rejected ************
ether_vid(423).
ether_vid(2134).
ether_vid(67).

% ***************** Database 7 :: Grammar of tcp destination addresses to be blocked and the packet to be rejected ************
proto_dst(55667).
proto_dst(57134).
proto_dst(62431).

% ***************** Database 8 :: Grammar of icmp types to be blocked and the packet to be rejected/dropped ************
icmp_port(7).
icmp_port(3).
icmp_port_drop(2). %****Drop the packet in this case****%

% *************************** End of Databases ****************




%use ranges if neededi
%*******range(X,Y,Z) :- X >= Y, X =< Z.**********



filter(X) :- reject(X) -> temp(reject); filter2(X).
filter2(X) :- drop(X) -> temp(bye); accept(X).

temp(reject) :- write("Packet Rejected"),nl.

temp(_) :- write("").

accept([A,B,C,D,E,F,G,H|_]) :- adapter(A),ether_proto(B),\+ether_vid(C),\+ip(D),\+ip_drop(D),proto(E),\+proto_src(F),\+proto_dst(G),\+icmp_port(H),\+icmp_port_drop(H),write("Packet Accepted").

reject([A,B,C,D,E,F,G,H|_]) :-(\+adapter(A);\+ether_proto(B);ether_vid(C);ip(D);\+proto(E);proto_src(F);proto_dst(G);icmp_port(H)),true.

drop([A,B,C,D,E,F,G,H|_])
:-(\+adapter(A);\+ether_proto(B);ether_vid(C);ip_drop(D);\+proto(E);proto_src(F);proto_dst(G);icmp_port_drop(H)).









