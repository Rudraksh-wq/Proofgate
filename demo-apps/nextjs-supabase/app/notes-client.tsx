"use client";

// Built "the Lovable way": the browser talks straight to Supabase with the public anon key and relies on
// row-level security (RLS) to keep people out of each other's notes. Which database variant is installed
// (supabase/variants/) decides whether that is true.
import { useCallback, useEffect, useState } from "react";
import { createClient } from "@/lib/supabase/client";
import { adminClient } from "@/lib/admin-client";

type Note = { id: string; user_id: string; title: string; body: string };

export default function NotesClient() {
  const supabase = createClient();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [userId, setUserId] = useState<string | null>(null);
  const [notes, setNotes] = useState<Note[]>([]);
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [message, setMessage] = useState("");

  const load = useCallback(async () => {
    const { data, error } = await supabase.from("notes").select("*").order("created_at");
    if (error) setMessage(error.message);
    else setNotes((data ?? []) as Note[]);
  }, [supabase]);

  useEffect(() => {
    supabase.auth.getUser().then(({ data }) => {
      setUserId(data.user?.id ?? null);
      if (data.user) void load();
    });
  }, [supabase, load]);

  async function signUp() {
    const { error } = await supabase.auth.signUp({ email, password });
    setMessage(error ? error.message : "Signed up. Now sign in.");
  }

  async function signIn() {
    const { data, error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) return setMessage(error.message);
    setUserId(data.user?.id ?? null);
    await load();
  }

  async function addNote() {
    if (!userId) return;
    const { error } = await supabase.from("notes").insert({ user_id: userId, title, body });
    if (error) setMessage(error.message);
    setTitle("");
    setBody("");
    await load();
  }

  async function removeNote(id: string) {
    await supabase.from("notes").delete().eq("id", id);
    await load();
  }

  // PLANTED (layers 2, 9): an "admin" button that needs the service_role key in the browser.
  async function adminDeleteAny(id: string) {
    await adminClient.from("notes").delete().eq("id", id);
    await load();
  }

  return (
    <section>
      {!userId ? (
        <div>
          <input placeholder="email" value={email} onChange={(e) => setEmail(e.target.value)} />
          <input placeholder="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          <button onClick={signIn}>Sign in</button>
          <button onClick={signUp}>Sign up</button>
        </div>
      ) : (
        <div>
          <input placeholder="title" value={title} onChange={(e) => setTitle(e.target.value)} />
          <input placeholder="body" value={body} onChange={(e) => setBody(e.target.value)} />
          <button onClick={addNote}>Add note</button>
        </div>
      )}
      <p role="status">{message}</p>
      <ul>
        {notes.map((n) => (
          <li key={n.id}>
            <b>{n.title}</b> {n.body}{" "}
            <button onClick={() => removeNote(n.id)}>delete</button>{" "}
            <button onClick={() => adminDeleteAny(n.id)}>admin delete</button>
          </li>
        ))}
      </ul>
    </section>
  );
}
