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
tcp_src(65530).
tcp_src(53789).
tcp_src(58779).

% ***************** Database 6 :: Grammar of VLAN identifiers to be blocked and the packet to be rejected ************
ether_vid(423).
ether_vid(2134).
ether_vid(67).

% ***************** Database 7 :: Grammar of tcp destination addresses to be blocked and the packet to be rejected ************
tcp_dst(55667).
tcp_dst(57134).
tcp_dst(62431).

% ***************** Database 8 :: Grammar of icmp types to be blocked and the packet to be rejected/dropped ************
icmp_port(7).
icmp_port(3).
icmp_port_drop(2). %****Drop the packet in this case****%

% ***************** Database 9 :: Grammar of udp source addresses to be blocked and the packet to be rejected ************
udp_src(1003).
udp_src(923).
udp_src(138).

% ***************** Database 10 :: Grammar of udp destination addresses
% to be blocked and the packet to be rejected ************
udp_dst(432).
udp_dst(561).
udp_dst(587).
% *************************** End of Databases ****************





%*******range(X,Y,Z) :- X >= Y, X =< Z.**********
%********You can try this out to specify ranges!!!*********

%max(X,Y,Max) :- if_then_else(X>Y,Max=X,Max=Y).


filter(X) :- reject(X) -> temp(hi); filter2(X).
filter2(X) :- drop(X) -> temp(bye); accept(X).

%filter([A,B,C,D,E,F,G,H,I,J|_]) :- if_then_else(reject([A,B,C,D,E,F,G,H,I,J|_]),temp(hi),filter2([A,B,C,D,E,F,G,H,I,J|_])).

%filter2([A,B,C,D,E,F,G,H,I,J|_]) :- if_then_else(drop([A,B,C,D,E,F,G,H,I,J|_]),temp(bye),accept([A,B,C,D,E,F,G,H,I,J|_])).

temp(_) :- write("lite"),nl.

accept([A,B,C,D,E,F,G,H,I,J|_]) :- adapter(A),ether_proto(B),\+ether_vid(C),\+ip(D),proto(E),\+tcp_src(F),\+tcp_dst(G),\+udp_src(H),\+udp_dst(I),\+icmp_port(J),write("Packet Accepted").

reject([A,B,C,D,E,F,G,H,I,J|_]) :-(\+adapter(A);\+ether_proto(B);ether_vid(C);ip(D);\+proto(E);tcp_src(F);tcp_dst(G);udp_src(H);udp_dst(I);icmp_port(J)),write("Packet Rejected").

drop([A,B,C,D,E,F,G,H,I,J|_]):-(\+adapter(A);\+ether_proto(B);ether_vid(C);ip_drop(D);\+proto(E);tcp_src(F);tcp_dst(G);udp_src(H);udp_dst(I);icmp_port_drop(J)).








