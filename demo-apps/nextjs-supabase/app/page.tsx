import NotesClient from "./notes-client";

export default function Home() {
  return (
    <main>
      <h1>Private notes</h1>
      <p>Only you should be able to see your notes. (Demo app for ProofGate: deliberately vulnerable, local only.)</p>
      <NotesClient />
    </main>
  );
}
