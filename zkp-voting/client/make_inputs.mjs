import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildTree, leafOf, nullifierOf, hex } from "./tree.mjs";
import { poseidon2 } from "poseidon-lite";

const root = fileURLToPath(new URL("../../circuits/", import.meta.url));
const secret = 987654321n;
const tree = buildTree([11n, 22n, 33n, secret].map(leafOf));
const { bits, sibs } = tree.path(3);
const electionId = BigInt(process.env.ZKP_TEST_ELECTION_ID ?? Date.now()), positionId = 1n, maxCandidates = 4;
const choice = [0, 1, 0, 0], rSeed = 55555n;
const pkX = 1n;
const pkY = 17631683881184975370165255887551781615748388533673675138860n;
const quote = (value) => `"${value}"`;
const boolean = (value) => value ? "true" : "false";
const encoderInputs = `pk_x = ${quote(pkX)}\npk_y = ${quote(pkY)}\nchoice = [${choice.map(quote).join(", ")}]\nr_seed = ${quote(rSeed)}\nmax_candidates = ${quote(maxCandidates)}\n`;
const encoderProver = `${root}/ballot_encoder/Prover.toml`;
const votingProver = `${root}/voting_circuit/Prover.toml`;
const originalEncoderProver = readFileSync(encoderProver, "utf8");
const originalVotingProver = readFileSync(votingProver, "utf8");
try {
	writeFileSync(encoderProver, encoderInputs);
	const encoderOutput = execFileSync("nargo", ["execute", "--package", "ballot_encoder"], { cwd: root }).toString();
	const circuitOutput = encoderOutput.match(/Circuit output: \[([^\]]+)\]/s);
	const values = circuitOutput ? [...circuitOutput[1].matchAll(/0x[0-9a-fA-F]+/g)].map(([value]) => BigInt(value)) : [];
	if (values.length !== 17) throw new Error(`Expected 17 encoder fields, received ${values.length}`);
	const commitment = values[16];
	const fieldHex = (value) => `0x${value.toString(16).padStart(64, "0")}`;
	const xs = [];
	let parityBits = 0;
	for (let slot = 0; slot < 4; slot++) {
		xs.push(fieldHex(values[slot * 4]), fieldHex(values[slot * 4 + 2]));
		parityBits |= Number(values[slot * 4 + 1] & 1n) << (slot * 2);
		parityBits |= Number(values[slot * 4 + 3] & 1n) << (slot * 2 + 1);
	}
	const fixture = {
		electionId: electionId.toString(),
		positionId: positionId.toString(),
		maxCandidates,
		root: fieldHex(tree.root),
		nullifier: fieldHex(nullifierOf(secret, electionId, positionId)),
		pkX: fieldHex(pkX),
		pkY: fieldHex(pkY),
		pkHash: fieldHex(poseidon2([pkX, pkY])),
		commitment: fieldHex(commitment),
		xs,
		parityBits,
	};
	writeFileSync(`${root}/target/voting_circuit.fixture.json`, `${JSON.stringify(fixture, null, 2)}\n`);
	writeFileSync(votingProver, `merkle_root_pub = ${quote(tree.root)}\nnullifier = ${quote(nullifierOf(secret, electionId, positionId))}\nelection_id = ${quote(electionId)}\nposition_id = ${quote(positionId)}\nmax_candidates = ${quote(maxCandidates)}\npk_hash = ${quote(poseidon2([pkX, pkY]))}\nballot_commitment = ${quote(commitment)}\ns = ${quote(secret)}\nbits = [${bits.map((bit) => boolean(bit === 1)).join(", ")}]\nsibs = [${sibs.map(quote).join(", ")}]\nchoice = [${choice.map((bit) => boolean(bit === 1)).join(", ")}]\nr_seed = ${quote(rSeed)}\npk_x = ${quote(pkX)}\npk_y = ${quote(pkY)}\n`);
	console.log("root      ", hex(tree.root));
	console.log("commitment", hex(commitment));
	console.log(execFileSync("nargo", ["execute", "--package", "voting_circuit"], { cwd: root }).toString().trim());
} finally {
	writeFileSync(encoderProver, originalEncoderProver);
	writeFileSync(votingProver, originalVotingProver);
}
