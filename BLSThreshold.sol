pragma solidity ^0.4.14;

/* 
-Pairing and other elliptic operations are based on the code from "https://gist.github.com/BjornvdLaan/ca6dd4e3993e1ef392f363ec27fe74c4"

-Test cases that provide inputs can be generated using BLS_2sign_testcase.py and BLS_2sign_testcase.py

** Be careful in inputs of type G2Point! 
*** G2 points in this code are represented in reverse order of BLS_test.py
** For example; G2 point of [1111,2222,3333,4444] in BLS_test.py is represented as a G2 point like G2Point([2222,1111],[4444,3333] in this code
*/

library BLSThreshold {
    struct G1Point {
        uint X;
        uint Y;
    }

    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }

    function G1() internal returns (G1Point) {
        return G1Point(1, 2);
    }

    function G2() internal returns (G2Point) {
        return G2Point(
            [11559732032986387107991004021392285783925812861821192530917403151452391805634,
            10857046999023057135944570762232829481370756359578518086990519993285655852781],

            [4082367875863433681332203403145435568316851327593401208105741076214120093531,
            8495653923123431417604973247489272438418190587263600148770280649306958101930]
        );
    }
    
    
    function test_sample_2signers() internal returns (bool){
        G1Point memory sample_sig1= G1Point(9804541985835767618765254686175434384734209305702261780457144743608049361074,1405734576804082306886516436753568532813082369641728912350118765887544375797);
        G1Point memory sample_sig2= G1Point(12998042674535415442796666425331582030340131363297918735509269751322370907776, 15791400145706132445870793197172305073525813587915570417662707190868074190524);

         G2Point memory sample_pubkey = G2Point(
            [13505823173380835868587575884635704883599421098297400455389802021584825778173, 6584456886510528562221720296624431746328412524156386210384049614268366928061],
            [17537837094362477976396927178636162167615173290927363003743794104386247847571, 5101591763860554569577488373372350852473588323930260132008193335489992486594]
        );
        
        bytes memory sample_message = "hello";
        
        return BLSVerify_2signers(sample_sig1,sample_sig2,sample_pubkey,sample_message);
        
    }
    
    function test_sample_3signers() internal returns (bool){
        G1Point memory sample_sig1= G1Point(4647509608584202165975782785954747159213898179310980386575835810736982209166,7253149301592985083560107979504991053757790718201732118929368515657051318307);
        G1Point memory sample_sig2= G1Point(7554407936293767798471215778909867099636057215540092296162695825040944708499, 1650169135864536438423777971407985152914176930600972561909148762692510732487);
        G1Point memory sample_sig3= G1Point(17467600538635543150510387015141499880964800763298463974971838640198822076343, 21480931349740415045399793252926822133910376439306446087157045996835974758768);
    
         G2Point memory sample_pubkey = G2Point(
            [9272593975849185657335483318454478620839867078185240916295924255880437119580, 9469223315397964882537666698959683629503616058292129208964089405000391238318],
            [164669229283707861373229048806442130090830374605771904452965626170114069219, 8425960337780795948248575290313339065443275509257741659613105125153003321225]
        );
        
        bytes memory sample_message = "hello";
        
        return BLSVerify_3signers(sample_sig1,sample_sig2,sample_sig3,sample_pubkey,sample_message);
        
    }
    
    function BLSVerify_2signers(G1Point sig1,G1Point sig2,G2Point pubkey,bytes message) internal returns (bool) {
        G1Point[] memory G1pts = new G1Point[](2);
        G2Point[] memory G2pts = new G2Point[](2);

        G1Point[] memory signatures = new G1Point[](3);
        signatures[0] = sig1;
        signatures[1] = sig2;

        G1Point memory aggregated_signature = aggregate_signatures(signatures);
        
        
        G1Point memory hash = hashToG1(message);
        
        G1pts[0] = negate(aggregated_signature);
        G1pts[1]= hash;
        G2pts[0]=G2();
        G2pts[1]= pubkey;
        
        return pairing(G1pts,G2pts);
    }
    
    function BLSVerify_3signers(G1Point sig1,G1Point sig2,G1Point sig3,G2Point pubkey,bytes message) internal returns (bool) {
        G1Point[] memory G1pts = new G1Point[](2);
        G2Point[] memory G2pts = new G2Point[](2);

        G1Point[] memory signatures = new G1Point[](3);
        signatures[0] = sig1;
        signatures[1] = sig2;
        signatures[2] = sig3;
        
        G1Point memory aggregated_signature = aggregate_signatures(signatures);
        
        
        G1Point memory hash = hashToG1(message);
        
        G1pts[0] = negate(aggregated_signature);
        G1pts[1]= hash;
        G2pts[0]=G2();
        G2pts[1]= pubkey;
        
        return pairing(G1pts,G2pts);
    }

    function aggregate_signatures(G1Point[] sigs) internal returns (G1Point agg_sig) {
        require(sigs.length != 0);
        uint numofSignatures = sigs.length;
        agg_sig = sigs[0];
        
         for (uint i = 1; i < numofSignatures; i++)
        {
            agg_sig = add(agg_sig,sigs[i]);
        }
        
    }
  
    function pairing(G1Point[] p1, G2Point[] p2) internal returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](6);

        for (uint i = 0; i < elements; i++)
        {
            input[0] = p1[i].X;
            input[1] = p1[i].Y;
            input[2] = p2[i].X[0];
            input[3] = p2[i].X[1];
            input[4] = p2[i].Y[0];
            input[5] = p2[i].Y[1];
        }

        uint[1] memory out;
        bool check;

        assembly {
            check := call(sub(gas, 2000), 8, 0, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)

            switch check case 0 {invalid}
        }
        require(check);
        return out[0] != 0;
    }

    function hashToG1(bytes message) internal returns (G1Point) {
        uint256 h = uint256(keccak256(message));
        return multiply(G1(), h);
    }

    function negate(G1Point p) internal returns (G1Point) {
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }

    function add(G1Point p1, G1Point p2) internal returns (G1Point r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := call(sub(gas, 2000), 6, 0, input, 0xc0, r, 0x60)

            switch success case 0 {invalid}
        }
        require(success);
    }
   
    function multiply(G1Point p, uint s) internal returns (G1Point r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := call(sub(gas, 2000), 7, 0, input, 0x80, r, 0x60)

            switch success case 0 {invalid}
        }
        require(success);
    }
}