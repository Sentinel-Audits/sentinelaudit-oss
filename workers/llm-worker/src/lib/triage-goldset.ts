import type { FindingTriageVerdict } from "./finding-triage";

export interface GoldSetFindingCase {
	id: string;
	title: string;
	detector: string;
	severity: "critical" | "high" | "medium" | "low" | "info";
	file: string;
	description: string;
	snippet: string;
	expectedVerdict: FindingTriageVerdict;
	why: string;
	tags: string[];
}

export const TRIAGE_GOLDSET_SEED: GoldSetFindingCase[] = [
	{
		id: "oz-init-reentrancy-benign",
		title: "Reentrancy Vulnerability (Benign)",
		detector: "reentrancy-benign",
		severity: "info",
		file: "contracts/vaults/OmniVaultShare.sol",
		description:
			"Reentrancy in OmniVaultShare.initialize(string,string,address) with endpoint.setDelegate before ownership writes.",
		snippet: [
			"function initialize(string memory _name, string memory _symbol, address _admin) public initializer {",
			'    require(_admin != address(0), "VS-SAZ-01");',
			"    __OFT_init(_name, _symbol, _admin);",
			"    __Ownable_init();",
			"    transferOwnership(_admin);",
			"}",
		].join("\n"),
		expectedVerdict: "likely_benign",
		why: "Initializer reentrancy has no demonstrated callback path into sensitive reachable logic before init completes.",
		tags: ["reentrancy", "initializer", "false-positive-pattern"],
	},
	{
		id: "unchecked-eth-send-real",
		title: "Arbitrary ETH Transfer",
		detector: "arbitrary-send-eth",
		severity: "high",
		file: "contracts/BorrowProtocol.sol",
		description:
			"BorrowProtocol.liquidate(address,uint256) sends collateral ETH to msg.sender before liquidation accounting is finalized.",
		snippet: [
			"function liquidate(address user, uint256 loanId) external {",
			"    Loan storage loan = loans[user][loanId];",
			"    (bool success,) = msg.sender.call{value: loan.collateralAmount}(\"\");",
			"    require(success, \"send failed\");",
			"    delete loans[user][loanId];",
			"}",
		].join("\n"),
		expectedVerdict: "likely_real",
		why: "Implementation snippet supports a concrete exploit path where caller-controlled payout happens before critical state finalization.",
		tags: ["funds-loss", "effects-after-interaction"],
	},
	{
		id: "delegate-wrapper-benign",
		title: "Incorrect Return Handling",
		detector: "incorrect-return",
		severity: "medium",
		file: "contracts/Proxy.sol",
		description: "Proxy._delegate() flagged for incorrect return handling.",
		snippet: [
			"assembly {",
			"  let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)",
			"  returndatacopy(0, 0, returndatasize())",
			"  switch result",
			"  case 0 { revert(0, returndatasize()) }",
			"  default { return(0, returndatasize()) }",
			"}",
		].join("\n"),
		expectedVerdict: "likely_benign",
		why: "This is a standard proxy forwarding pattern and a known static-analysis false positive.",
		tags: ["proxy", "known-false-positive"],
	},
	{
		id: "tx-origin-auth-real",
		title: "Dangerous tx.origin Usage",
		detector: "tx-origin",
		severity: "high",
		file: "contracts/Treasury.sol",
		description: "Treasury.withdraw() authorizes withdrawals with tx.origin == owner.",
		snippet: [
			"function withdraw(address payable to, uint256 amount) external {",
			"    require(tx.origin == owner, \"not owner\");",
			"    (bool ok,) = to.call{value: amount}(\"\");",
			"    require(ok);",
			"}",
		].join("\n"),
		expectedVerdict: "likely_real",
		why: "The implementation directly relies on tx.origin for authorization and exposes a realistic phishing-mediated bypass.",
		tags: ["auth", "phishing"],
	},
	{
		id: "owner-upgrade-needs-review",
		title: "Unprotected Upgrade",
		detector: "unprotected-upgrade",
		severity: "high",
		file: "contracts/UpgradeableVault.sol",
		description: "Upgrade path may be callable without sufficient access control.",
		snippet: [
			"function upgradeTo(address newImplementation) external {",
			"    _upgradeTo(newImplementation);",
			"}",
		].join("\n"),
		expectedVerdict: "needs_human_review",
		why: "The snippet is risky and likely missing auth, but exploitability still depends on inherited guards or surrounding proxy wiring not shown here.",
		tags: ["upgradeability", "context-dependent"],
	},
	{
		id: "dead-code-benign",
		title: "Dead Code",
		detector: "dead-code",
		severity: "info",
		file: "contracts/Helpers.sol",
		description: "Function _unusedHelper() is never used.",
		snippet: "function _unusedHelper() internal pure returns (uint256) { return 1; }",
		expectedVerdict: "likely_benign",
		why: "This is maintenance noise, not a reportable security issue.",
		tags: ["advisory", "noise"],
	},
];
