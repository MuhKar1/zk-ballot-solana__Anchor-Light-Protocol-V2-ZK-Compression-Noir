import Link from "next/link";

export default function Home({ searchParams }: { searchParams?: { done?: string } }) {
  const done = typeof searchParams?.done === "string" ? searchParams.done : undefined;

  const success =
    done === "voter"
      ? {
          title: "✅ Thank you for voting!",
          body: "Your encrypted ballot was recorded on-chain. Your choices stay private, and anyone can verify the results once they're published.",
        }
      : done === "admin"
        ? {
            title: "🗳️ Election setup complete!",
            body: "Your election is live and the voter list is locked. Share the manifest with your voters, and post the tally after voting ends.",
          }
        : null;

  return (
    <div className="container">
      {success && (
        <div className="alert alert-success" style={{ marginTop: 8 }}>
          <strong>{success.title}</strong>
          <p style={{ margin: "6px 0 0" }}>{success.body}</p>
        </div>
      )}

      <div className="hero">
        <h1>Zero-knowledge voting on Solana</h1>
        <p>
          Private, verifiable elections. Votes are encrypted under ElGamal over Grumpkin, proven
          eligible with a Noir Groth16 circuit, and committed to chain via Light Protocol V2
          compressed accounts — then tallied by another on-chain proof.
        </p>
      </div>

      <div className="cards">
        <Link href="/admin" className="card">
          <h2>🗳️ Admin console</h2>
          <p className="hint" style={{ margin: "8px 0 0" }}>
            Create an election, lock the voter list, and publish verifiable results.
          </p>
        </Link>
        <Link href="/vote" className="card">
          <h2>✅ Voter booth</h2>
          <p className="hint" style={{ margin: "8px 0 0" }}>
            Identify with your ID + password, choose a candidate, and cast an encrypted ballot.
          </p>
        </Link>
        <Link href="/results" className="card">
          <h2>📊 Results</h2>
          <p className="hint" style={{ margin: "8px 0 0" }}>
            Inspect the live transcript and the on-chain verified tally.
          </p>
        </Link>
      </div>
    </div>
  );
}
