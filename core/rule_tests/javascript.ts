// Test cases for rules/javascript.yaml (semgrep --test convention). Deliberately vulnerable, never executed.
declare const el: any, cp: any, sb: any, userHtml: string, cmd: string, sql: string, cors: any, process: any;

// ruleid: proofgate.js-dangerously-set-inner-html
const a = <div dangerouslySetInnerHTML={{ __html: userHtml }} />;
// ok: proofgate.js-dangerously-set-inner-html
const b = <div dangerouslySetInnerHTML={{ __html: "<b>static</b>" }} />;

// ruleid: proofgate.js-innerhtml-assignment
el.innerHTML = userHtml;
// ok: proofgate.js-innerhtml-assignment
el.innerHTML = "<b>static</b>";

// ruleid: proofgate.js-eval
eval(userHtml);
// ruleid: proofgate.js-eval
const f = new Function("a", userHtml);
// ok: proofgate.js-eval
eval("1 + 1");

// ruleid: proofgate.js-child-process-exec
cp.exec(`ls ${cmd}`);
// ruleid: proofgate.js-child-process-exec
cp.execSync("ls " + cmd);
// ok: proofgate.js-child-process-exec
cp.execFile("ls", [cmd]);

// ruleid: proofgate.js-supabase-rpc-string-sql
sb.rpc("run_sql", { query: `select * from notes where id = ${sql}` });
// ok: proofgate.js-supabase-rpc-string-sql
sb.rpc("get_note", { note_id: sql });

// ruleid: proofgate.js-public-env-secret
const k1 = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;
// ok: proofgate.js-public-env-secret
const k2 = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

// ruleid: proofgate.js-cors-wildcard-credentials
cors({ origin: "*", credentials: true });
// ok: proofgate.js-cors-wildcard-credentials
cors({ origin: "https://app.example.com", credentials: true });
