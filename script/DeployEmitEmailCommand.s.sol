// SPDX-License-Identifier: MIT

pragma solidity ^0.8.10;

import "forge-std/Script.sol";

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@zk-email/ether-email-auth-contracts/src/utils/Verifier.sol";
import "@zk-email/ether-email-auth-contracts/src/utils/Groth16Verifier.sol";
import "@zk-email/ether-email-auth-contracts/src/utils/ECDSAOwnedDKIMRegistry.sol";
import "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import "../src/EmitEmailCommand.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract Deploy is Script {
    using ECDSA for *;

    ECDSAOwnedDKIMRegistry dkimImpl;
    ECDSAOwnedDKIMRegistry dkim;
    Verifier verifierImpl;
    Verifier verifier;
    EmailAuth emailAuthImpl;
    EmitEmailCommand emitEmailCommand;

    function run() external {
        uint256 deployerPK = vm.envUint("DEPLOYER_PK");
        if (deployerPK == 0) {
            console.log("DEPLOYER_PK not set yet");
            return;
        }
        address signer = vm.envAddress("SIGNER");
        if (signer == address(0)) {
            console.log("SIGNER not set yet");
            return;
        }
        vm.startBroadcast(deployerPK);
        address initialOwner = vm.addr(deployerPK);
        console.log("Init Owne: %s", vm.toString(initialOwner));

        // Deploy ECDSA DKIM registry
        {
            dkimImpl = new ECDSAOwnedDKIMRegistry();
            console.log(
                "ECDSAOwnedDKIMRegistry implementation deployed at: %s",
                address(dkimImpl)
            );
            ERC1967Proxy dkimProxy = new ERC1967Proxy(
                address(dkimImpl),
                abi.encodeCall(
                    ECDSAOwnedDKIMRegistry.initialize,
                    (initialOwner, signer)
                )
            );
            dkim = ECDSAOwnedDKIMRegistry(address(dkimProxy));
            console.log(
                "ECDSAOwnedDKIMRegistry (proxy) deployed at: %s",
                address(dkim)
            );
            vm.setEnv("ECDSA_DKIM", vm.toString(address(dkim)));
        }

        // Deploy Verifier
        {
            verifierImpl = new Verifier();
            console.log(
                "verifier implementation contract deployed at: %s",
                address(verifierImpl)
            );
            Groth16Verifier groth16Verifier = new Groth16Verifier();
            ERC1967Proxy verifierProxy = new ERC1967Proxy(
                address(verifierImpl),
                abi.encodeCall(
                    Verifier.initialize,
                    (initialOwner, address(groth16Verifier))
                )
            );
            verifier = Verifier(address(verifierProxy));
            console.log("Verifier (proxy) deployed at: %s", address(verifier));
            vm.setEnv("VERIFIER", vm.toString(address(verifier)));
        }

        //Deploy EmailAuth Implementation
        {
            emailAuthImpl = new EmailAuth();
            console.log(
                "EmailAuth implementation deployed at: %s",
                address(emailAuthImpl)
            );
            vm.setEnv("EMAIL_AUTH_IMPL", vm.toString(address(emailAuthImpl)));
        }

        //Deploy EmitEmailCommand
        {
            emitEmailCommand = new EmitEmailCommand(
                address(verifier),
                address(dkim),
                address(emailAuthImpl)
            );
            console.log(
                "EmitEmailCommand deployed at: %s",
                address(emitEmailCommand)
            );
        }
        vm.stopBroadcast();
    }
}
