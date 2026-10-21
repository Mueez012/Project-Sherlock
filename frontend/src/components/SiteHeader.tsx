"use client";

import { Crosshair, Plus } from "@phosphor-icons/react";
import Link from "next/link";

import { ThemeToggle } from "@/components/ThemeToggle";

export function Logo() {
  return (
    <Link className="brand" href="/" aria-label="Sherklock Honed home">
      <span className="brand-mark" aria-hidden="true"><Crosshair weight="bold" /></span>
      <span>Sherklock <b>Honed</b></span>
    </Link>
  );
}

export function SiteHeader({ onNewAnalysis, links = true }: { onNewAnalysis: () => void; links?: boolean }) {
  return (
    <header className="site-header">
      <nav className="site-nav" aria-label="Main navigation">
        <Logo />
        {links && (
          <div className="nav-links">
            <Link href="/#how">How it works</Link>
            <Link href="/#recent">Recent analyses</Link>
            <Link href="/#roadmap">Attribution (preview)</Link>
          </div>
        )}
        <div className="nav-actions">
          <ThemeToggle />
          <button type="button" className="button primary" onClick={onNewAnalysis} aria-label="New analysis">
            <Plus aria-hidden="true" weight="bold" /> <span className="hide-sm">New analysis</span>
          </button>
        </div>
      </nav>
    </header>
  );
}
