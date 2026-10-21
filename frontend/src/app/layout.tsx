import "@fontsource-variable/inter";
import "@fontsource-variable/geist-mono";
import type { Metadata } from "next";

import { THEME_INIT_SCRIPT } from "@/components/ThemeToggle";

import "../styles/tokens.css";
import "../styles/base.css";
import "../styles/components.css";
import "../styles/landing.css";
import "../styles/analysis.css";

export const metadata: Metadata = {
  title: "Sherklock Honed: CTI report to ATT&CK",
  description: "Extract MITRE ATT&CK tactics and techniques from threat reports, with the evidence behind every result.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* Sets data-theme before the first paint so a saved theme never flashes. */}
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }} />
      </head>
      <body>
        <a className="skip-link" href="#main">Skip to content</a>
        {children}
      </body>
    </html>
  );
}
