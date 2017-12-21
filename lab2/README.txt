build:
% make re

run:
% ./skgu_pki init 
% ./skgu_pki cert -g alice.priv alice.pub alice 
% ./skgu_pki cert -g bob.priv bob.pub bob 
% ./skgu_nidh alice.priv alice.cert alice bob.pub bob.cert bob example1
% ./skgu_nidh bob.priv bob.cert bob alice.pub alice.cert alice example1
% ls example1-alice.*
% ls example1-bob.*
% diff example1-alice.b64 example1-bob.b64
% cat example1-alice.b64
% cat example1-bob.b64

-make clean: removes .pub .cert .priv .b64 files
-make re: make clean -> make all

