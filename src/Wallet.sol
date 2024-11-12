// SPDX-License-Identifier: MIT

pragma solidity ^0.8.10;

import "@zk-email/ether-email-auth-contracts/src/EmailAuth.sol";
import "@openzeppelin/contracts/utils/Create2.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "./lib/WebAuthn.sol";

contract Wallet {
    address public verifierAddr;
    address public dkimAddr;
    address public emailAuthImplAddr;
    uint[2] public passkeyPub;

    event PasskeyBinding(address indexed emailAuthAddr, uint[2] indexed pubkey);

    constructor(
        address _verifierAddr,
        address _dkimAddr,
        address _emailAuthImpAddr
    ) {
        verifierAddr = _verifierAddr;
        dkimAddr = _dkimAddr;
        _emailAuthImpAddr = _emailAuthImpAddr;
    }

    /// @notice Returns the address of the verifier contract.
    /// @dev This function is virtual and can be overridden by inheriting contracts.
    /// @return address The address of the verifier contract.
    function verifier() public view virtual returns (address) {
        return verifierAddr;
    }

    /// @notice Returns the address of the DKIM contract.
    /// @dev This function is virtual and can be overridden by inheriting contracts.
    /// @return address The address of the DKIM contract.
    function dkim() public view virtual returns (address) {
        return dkimAddr;
    }

    /// @notice Returns the address of the email auth contract implementation.
    /// @dev This function is virtual and can be overridden by inheriting contracts.
    /// @return address The address of the email authentication contract implementation.
    function emailAuthImplementation() public view virtual returns (address) {
        return emailAuthImplAddr;
    }

    /// @notice Computes the address for email auth contract using the CREATE2 opcode.
    /// @dev This function utilizes the `Create2` library to compute the address. The computation uses a provided account address to be recovered, account salt,
    /// and the hash of the encoded ERC1967Proxy creation code concatenated with the encoded email auth contract implementation
    /// address and the initialization call data. This ensures that the computed address is deterministic and unique per account salt.
    /// @param owner The address of the owner of the EmailAuth proxy.
    /// @param accountSalt A bytes32 salt value defined as a hash of the guardian's email address and an account code. This is assumed to be unique to a pair of the guardian's email address and the wallet address to be recovered.
    /// @return address The computed address.
    function computeEmailAuthAddress(
        address owner,
        bytes32 accountSalt
    ) public view returns (address) {
        return
            Create2.computeAddress(
                accountSalt,
                keccak256(
                    abi.encodePacked(
                        type(ERC1967Proxy).creationCode,
                        abi.encode(
                            emailAuthImplementation(),
                            abi.encodeCall(
                                EmailAuth.initialize,
                                (owner, accountSalt, address(this))
                            )
                        )
                    )
                )
            );
    }

    /// @notice Deploys a new proxy contract for email authentication.
    /// @dev This function uses the CREATE2 opcode to deploy a new ERC1967Proxy contract with a deterministic address.
    /// @param owner The address of the owner of the EmailAuth proxy.
    /// @param accountSalt A bytes32 salt value used to ensure the uniqueness of the deployed proxy address.
    /// @return address The address of the newly deployed proxy contract.
    function deployEmailAuthProxy(
        address owner,
        bytes32 accountSalt
    ) internal returns (address) {
        ERC1967Proxy proxy = new ERC1967Proxy{salt: accountSalt}(
            emailAuthImplementation(),
            abi.encodeCall(
                EmailAuth.initialize,
                (owner, accountSalt, address(this))
            )
        );
        return address(proxy);
    }

    /// @notice Calculates a unique command template ID for template provided by this contract.
    /// @dev Encodes "EXAMPLE", and the template index,
    /// then uses keccak256 to hash these values into a uint ID.
    /// @param templateIdx The index of the command template.
    /// @return uint The computed uint ID.
    function computeTemplateId(uint templateIdx) public pure returns (uint) {
        return uint256(keccak256(abi.encode("EXAMPLE", templateIdx)));
    }

    /**
     * @notice Returns a two-dimensional array of strings representing the command templates.
     * @return string[][] A two-dimensional array of strings,
     *    where each inner array represents a set of fixed strings and matchers for a command template.
     * templates struct is a two-dimensional array of strings:
     *    each row represents an acceptable command, each element in this row combined together to represent the comman format
     */
    function commandTemplates() public pure returns (string[][] memory) {
        string[][] memory templates = new string[][](1);
        templates[0] = new string[](4);
        templates[0][0] = "Bind";
        templates[0][1] = "Pubkey";
        templates[0][2] = "{uint}";
        templates[0][3] = "{uint}";

        return templates;
    }

    /// @notice Bind the Passkey stated in the given email
    function BindPasskey(
        EmailAuthMsg memory emailAuthMsg,
        address owner,
        uint templateIdx
    ) public {
        address emailAuthAddr = computeEmailAuthAddress(
            owner,
            emailAuthMsg.proof.accountSalt
        );
        uint templateId = computeTemplateId(templateIdx);
        require(templateId == emailAuthMsg.templateId, "invalid template Id");

        EmailAuth emailAuth;
        // Deploy the EmailAuth contract if it hasn't been deployed
        if (emailAuthAddr.code.length == 0) {
            require(
                emailAuthMsg.proof.isCodeExist == true,
                "isCodeExist should be true for the first email"
            );
            address proxyAddr = deployEmailAuthProxy(
                owner,
                emailAuthMsg.proof.accountSalt
            );
            require(
                proxyAddr == emailAuthAddr,
                "proxy address does not match emailAuthAdrr"
            );
            emailAuth = EmailAuth(proxyAddr);

            //Initial setup for new deployed email auth contract
            emailAuth.initDKIMRegistry(dkim());
            emailAuth.initVerifier(verifierAddr);
            string[][] memory templates = commandTemplates();
            //Set template for new deployed email auth contract
            for (uint idx = 0; idx < templates.length; idx++) {
                emailAuth.insertCommandTemplate(
                    computeTemplateId(idx),
                    templates[idx]
                );
            }
        } else {
            emailAuth = EmailAuth(emailAuthAddr);
            require(
                emailAuth.controller() == address(this),
                "invalid controller"
            );
        }

        emailAuth.authEmail(emailAuthMsg);
        _bindPasskey(emailAuthAddr, emailAuthMsg.commandParams);
    }

    function addTestPasskey(uint[2] memory _passkey) external {
        passkeyPub = _passkey;
    }

    function checkPasskeySig(
        bytes memory challenge,
        bytes memory authenticatorData,
        string memory clientDataJSON,
        uint challengeLocation,
        uint responseTypeLocation,
        uint r,
        uint s
    ) public view returns (bool) {
        return
            WebAuthn.verifySignature({
                challenge: challenge,
                authenticatorData: authenticatorData,
                requireUserVerification: false,
                clientDataJSON: clientDataJSON,
                challengeLocation: challengeLocation,
                responseTypeLocation: responseTypeLocation,
                r: r,
                s: s,
                x: passkeyPub[0],
                y: passkeyPub[1]
            });
    }

    function _bindPasskey(
        address emailAuthAddr,
        bytes[] memory commandParams
    ) private {
        uint pubkey1 = abi.decode(commandParams[0], (uint));
        uint pubkey2 = abi.decode(commandParams[1], (uint));
        passkeyPub[0] = pubkey1;
        passkeyPub[1] = pubkey2;
        emit PasskeyBinding(emailAuthAddr, passkeyPub);
    }
}
