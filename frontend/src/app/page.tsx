"use client";

import { useGSAP } from "@gsap/react";
import {
  ArrowDown, ArrowRight, Brain, CheckCircle, FileText, Flask, ListChecks, Scissors,
} from "@phosphor-icons/react";
import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import Link from "next/link";
import { useRef, useState } from "react";

import { ConfidenceBadge } from "@/components/ConfidenceBadge";
import { Logo, SiteHeader } from "@/components/SiteHeader";
import { AnalyzeDialog } from "@/features/analysis/AnalyzeDialog";
import { DEMO_ACTORS } from "@/features/landing/demoData";
import { TACTIC_NAME } from "@/lib/attack";
import sample from "@/mocks/analysis-result.json";
import type { AnalysisResult } from "@/types/analysis";

gsap.registerPlugin(ScrollTrigger, useGSAP);

const SAMPLE = sample as AnalysisResult;
const FORMATS = ["Pasted report text", "MITRE ATT&CK v14", "14 tactics", "189 techniques", "Indicators of compromise"];

const STEPS = [
  { icon: FileText, title: "Paste the report", copy: "The text goes to the hub, which runs every module on it and combines their answers." },
  { icon: Scissors, title: "Split into sentences", copy: "The hub splits the text once, the same way the training data was split, so every module numbers sentences alike." },
  { icon: Brain, title: "Classify every sentence", copy: "SecureBERT reads each sentence; the ThreatMAMBA head scores 14 tactics and 189 techniques. Indicators are extracted too." },
  { icon: ListChecks, title: "Combine with evidence", copy: "Sentence scores become one list of techniques and indicators, each with the sentences that support it." },
];

function DemoBadge() {
  return <span className="demo-badge"><Flask aria-hidden="true" weight="fill" /> Demo data · attribution coming later</span>;
}

function Hero({ onCreate }: { onCreate: () => void }) {
  const top = SAMPLE.techniques.slice(0, 5);
  return (
    <section className="hero" id="top">
      <div className="hero-copy">
        <p className="eyebrow">CTI report → MITRE ATT&amp;CK</p>
        <h1>Turn threat reports into ATT&amp;CK techniques, with the evidence attached.</h1>
        <p className="lead">
          Paste a CTI report. Sherklock Honed reads it sentence by sentence, finds the tactics, techniques and
          indicators it describes, and shows the exact sentences behind every result.
        </p>
        <div className="hero-actions">
          <button type="button" className="button primary large" onClick={onCreate}>
            Analyse a report <ArrowRight aria-hidden="true" weight="bold" />
          </button>
          <Link className="button secondary large" href="/sample">See a sample result</Link>
        </div>
      </div>
      <figure className="hero-preview card">
        <figcaption>
          <span className="eyebrow">Sample result</span>
          <span className="muted small">synthetic report · {SAMPLE.summary.n_techniques} techniques</span>
        </figcaption>
        <ul>
          {top.map((t) => (
            <li key={t.id}>
              <span className="mono">{t.id}</span>
              <span className="preview-name">{t.name}<small>{t.tactic_ids.map((id) => TACTIC_NAME[id]).join(", ")}</small></span>
              <ConfidenceBadge value={t.confidence} band={t.band} compact />
            </li>
          ))}
        </ul>
        <blockquote className="preview-evidence">
          <span className="small muted">Evidence for {top[0]?.id}</span>
          “{top[0]?.evidence[0]?.text}”
        </blockquote>
      </figure>
    </section>
  );
}

function FormatStrip() {
  return (
    <div className="format-strip" aria-label="Supported inputs and standards">
      {FORMATS.map((f) => <span key={f}>{f}</span>)}
    </div>
  );
}

function HowItWorks({ onCreate }: { onCreate: () => void }) {
  return (
    <section className="section" id="how" aria-labelledby="how-title">
      <div className="section-intro">
        <p className="eyebrow">How it works</p>
        <h2 id="how-title">From messy report to a list of techniques you can check.</h2>
      </div>
      <ol className="steps">
        {STEPS.map(({ icon: Icon, title, copy }, i) => (
          <li key={title} className="card reveal">
            <span className="step-number mono">0{i + 1}</span>
            <Icon size={28} aria-hidden="true" weight="duotone" />
            <h3>{title}</h3>
            <p>{copy}</p>
          </li>
        ))}
      </ol>
      <div className="card honesty reveal">
        <CheckCircle size={24} aria-hidden="true" weight="fill" />
        <p>
          Every score is a model probability, not a verified finding. Confidence is shown as a number and a
          band (high ≥ 80%, medium 50–79%, low below 50%), and each technique links to the sentences that triggered it.
        </p>
        <button type="button" className="button primary" onClick={onCreate}>Start an analysis <ArrowRight aria-hidden="true" /></button>
      </div>
    </section>
  );
}

function AttributionPreview() {
  const [selected, setSelected] = useState(0);
  const actor = DEMO_ACTORS[selected];
  return (
    <section className="section" id="roadmap" aria-labelledby="roadmap-title">
      <div className="section-intro split">
        <div>
          <p className="eyebrow">Next phase</p>
          <h2 id="roadmap-title">Ranked attribution, with proof attached.</h2>
        </div>
        <div>
          <DemoBadge />
          <p className="muted">
            The planned second stage compares extracted techniques with known threat-actor behaviour.
            This preview uses made-up numbers; the current API does not produce attribution.
          </p>
        </div>
      </div>
      <div className="attribution reveal" aria-label="Attribution preview with demo data">
        <div className="card actor-table">
          <div className="actor-head" aria-hidden="true"><span>Candidate actor</span><span>Origin</span><span>Score</span></div>
          {DEMO_ACTORS.map((a, i) => (
            <button type="button" key={a.name} className={`actor-row ${selected === i ? "active" : ""}`}
              aria-pressed={selected === i} onClick={() => setSelected(i)}>
              <span className="mono rank">0{i + 1}</span>
              <span className="actor-identity"><b>{a.name}</b><small>{a.alias}</small></span>
              <span className="origin">{a.origin}</span>
              <span className="actor-score"><b className="mono">{a.confidence}%</b><i><em className={`tone-${a.tone}`} style={{ width: `${a.confidence}%` }} /></i></span>
            </button>
          ))}
        </div>
        <aside className="card explain-panel">
          <div className="explain-head"><h3>Why {actor.name}?</h3><span className="mono">{actor.confidence}% (demo)</span></div>
          <p className="muted small">Contribution to the illustrative score.</p>
          <ul className="evidence-bars">
            {actor.evidence.map((item) => (
              <li key={item.label}>
                <div><span>{item.label}</span><b className="mono">{item.value}%</b></div>
                <i><em className={`tone-${actor.tone}`} style={{ width: `${item.value * 3}%` }} /></i>
              </li>
            ))}
          </ul>
        </aside>
      </div>
    </section>
  );
}

// Plain text on purpose: the old word-by-word fade left text at 25% opacity (fails contrast).
function Statement() {
  return (
    <section className="statement">
      <p>Attribution should never be a black box. Every conclusion should point back to the sentences, behaviours and evidence that shaped it.</p>
    </section>
  );
}

function Closing({ onCreate }: { onCreate: () => void }) {
  return (
    <section className="closing">
      <h2>Bring a report. Leave with evidence.</h2>
      <div className="hero-actions">
        <button type="button" className="button primary large" onClick={onCreate}>Analyse a report <ArrowRight aria-hidden="true" weight="bold" /></button>
        <a className="button secondary large" href="#top">Back to top <ArrowDown aria-hidden="true" className="flip" /></a>
      </div>
    </section>
  );
}

export default function Home() {
  const pageRef = useRef<HTMLElement>(null);
  const [uploadOpen, setUploadOpen] = useState(false);
  const open = () => setUploadOpen(true);

  useGSAP(() => {
    const mm = gsap.matchMedia();
    mm.add("(prefers-reduced-motion: no-preference)", () => {
      gsap.utils.toArray<HTMLElement>(".reveal").forEach((el) => {
        gsap.fromTo(el, { y: 24, opacity: 0 }, {
          y: 0, opacity: 1, duration: 0.5, ease: "power2.out",
          scrollTrigger: { trigger: el, start: "top 90%", once: true },
        });
      });
    });
    return () => mm.revert();
  }, { scope: pageRef });

  return (
    <>
      <SiteHeader onNewAnalysis={open} />
      <main className="page" id="main" ref={pageRef}>
        <Hero onCreate={open} />
        <FormatStrip />
        <HowItWorks onCreate={open} />
        <AttributionPreview />
        <Statement />
        <Closing onCreate={open} />
      </main>
      <footer className="site-footer">
        <Logo />
        <p className="muted">ThreatMAMBA TTP extraction · FYP proof of concept, FAST-NUCES</p>
        <span className="mono muted">2026</span>
      </footer>
      <AnalyzeDialog open={uploadOpen} onClose={() => setUploadOpen(false)} />
    </>
  );
}
