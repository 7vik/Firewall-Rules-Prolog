%  ********************** CS F214 Assignment - Firewall Rules on Incoming Packets ****************************
% Member1 => Satvik Golechha - 2017A7PS0117P
% Member2 => Bharat Bhargava - 2017A7PS0025P

%***********************************DATABASES AND GRAMMARS*****************************************
%
% ****DB1::adapter clauses allowed*************
%
adapter(a).
adapter(d).
adapter(g).
%
%***********DB2::protocols allowed************
%
proto('UDP').
proto('TCP').
proto('ICMP').
%
% **DB3::ethernet protocols allowed************
%
ether_proto(0x86dd).
ether_proto(0x0800).
ether_proto(0xf002).
ether_proto(0xaa38).
%
% ***DB4::ip blocked and the packet dropped/rejected*******
%
ip('172.24.16.31').
ip('192.26.26.250').
ip('187.24.31.6').
ip_drop('172.27.18.213'). %****Drop the packet in this case****%
ip_drop('191.25.22.123'). %****Drop the packet in this case****%
%
% ***************** DB5::tcp source addresses blocked and packet rejected********
%
proto_src(65530).
proto_src(53789).
proto_src(58779).
%
% ************DB6::VLAN identifiers blocked and packet rejected*******
ether_vid(423).
ether_vid(2134).
ether_vid(67).
%
% ***************** DB7::tcp dest addr blocked and packet rejected************
%
proto_dst(55667).
proto_dst(57134).
proto_dst(62431).
%
% ***************** DB8::icmp types blocked and packet rejected/dropped********
%
icmp_port(7).
icmp_port(3).
icmp_port_drop(2). %****Drop the packet in this case****
%
% ********************************************** END OF DATABASES ***************************************


%


my_range(A,B,C) :- A>=B, A=<C.

%setting correct precedence order for reject > drop > accept
filter(X) :- reject(X) -> stdout(reject); filter2(X).
filter2(X) :- drop(X) -> stdout(null); filter3(X).
filter3(X) :- accept(X) -> stdout(accept); stdout(invalid).


%term functor to display filter operation on the standard output
stdout(reject) :- write("Packet Rejected"),nl.
stdout(accept) :- write("Packet Accepted"),nl.
stdout(invalid) :- write("Invalid Packet"),nl.
stdout(_) :- write("").


%%definitions for accept, reject, and drop
accept([A,B,C,D,E,F,G,H|_]) :-     adapter(A),
                               ether_proto(B),
                               \+ether_vid(C),
                                      \+ip(D),
                                 \+ip_drop(D),
                                     proto(E),
                               \+proto_src(F),
                               \+proto_dst(G),
                               \+icmp_port(H),
                          \+icmp_port_drop(H),
                           my_range(C,1,4095),
                          my_range(F,0,65535),
                          my_range(G,0,65535).


reject([A,B,C,D,E,F,G,H|_]) :-    (\+adapter(A);
                                \+ether_proto(B);
                                    ether_vid(C);
                                           ip(D);
                                      \+proto(E);
                                    proto_src(F);
                                    proto_dst(G);
                                   icmp_port(H)),
                              my_range(C,1,4095),
                             my_range(F,0,65535),
                             my_range(G,0,65535).

drop([A,B,C,D,E,F,G,H|_]) :-        (\+adapter(A);
                                 \+ether_proto(B);
                                     ether_vid(C);
                                       ip_drop(D);
                                       \+proto(E);
                                     proto_src(F);
                                     proto_dst(G);
                               icmp_port_drop(H)),
                               my_range(C,1,4095),
                              my_range(F,0,65535),
                              my_range(G,0,65535).

%/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\ THANK YOU /\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/
