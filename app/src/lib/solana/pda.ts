import { PublicKey } from "@solana/web3.js";
import BN from "bn.js";

/** [ "election", authority, election_id_le ] */
export function electionPda(
  authority: PublicKey,
  electionId: BN,
  programId: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("election"), authority.toBuffer(), electionId.toArrayLike(Buffer, "le", 8)],
    programId
  );
}

/** [ "position", election, position_id_le ] */
export function positionPda(
  election: PublicKey,
  positionId: BN,
  programId: PublicKey
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("position"), election.toBuffer(), positionId.toArrayLike(Buffer, "le", 8)],
    programId
  );
}

/** [ "transcript", position ] */
export function transcriptPda(position: PublicKey, programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("transcript"), position.toBuffer()],
    programId
  );
}

/** [ "tally", position ] */
export function tallyPda(position: PublicKey, programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from("tally"), position.toBuffer()], programId);
}

/** [ "cpi_authority" ] — the Light V2 CPI signer seed. */
export function cpiSignerPda(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from("cpi_authority")], programId);
}

export function toBn(value: bigint | number | string): BN {
  return new BN(value.toString());
}
