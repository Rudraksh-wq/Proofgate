import type { ReactNode } from "react";
import "./globals.css";
import { LIMITS_STATEMENT } from "@/lib/site";

export const metadata = {
  title: "ProofGate: a local security gate for AI-written apps",
  description:
    "ProofGate runs 9 layers of checks, proves access-control bugs by attacking your app as a second user on your own machine, and accepts a fix only when the attack fails and your feature still works. Your code never leaves your laptop.",
};

const NAV = [
  ["/install/", "Install"],
  ["/how-it-works/", "How it works"],
  ["/limits/", "Limits"],
  ["/benchmark/", "Benchmark"],
  ["/llms.txt", "llms.txt"],
];

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="site">
          <div className="wrap">
            <a className="brand" href="/">ProofGate</a>
            <nav aria-label="Main">
              {NAV.map(([href, label]) => (
                <a key={href} href={href}>{label}</a>
              ))}
            </nav>
          </div>
        </header>
        <main>
          <div className="wrap">{children}</div>
        </main>
        <footer className="site">
          <div className="wrap">
            <p>{LIMITS_STATEMENT}</p>
            <p>This site never scans, uploads or stores code. It has no forms, no accounts and no analytics.</p>
          </div>
        </footer>
      </body>
    </html>
  );
}
