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
%


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


reject([A,B,C,D,E,F,G,H|_]) :-    ( \+adapter(A);
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

drop([A,B,C,D,E,F,G,H|_]) :-       ( \+adapter(A);
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

% /\/\/\/\/\\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\ THANK YOU /\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/\/








