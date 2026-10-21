// DEMO DATA for the attribution preview sections. Attribution is NOT produced by
// the current API (it extracts TTPs only); these numbers are illustrative.
export type Tone = "t1" | "t2" | "t3" | "t4";

export interface DemoActor {
  name: string;
  alias: string;
  origin: string;
  confidence: number;
  tone: Tone;
  evidence: { label: string; value: number }[];
}

export const DEMO_ACTORS: DemoActor[] = [
  { name: "APT29", alias: "Cozy Bear", origin: "Russia", confidence: 87.4, tone: "t1", evidence: [
    { label: "T1059.001 PowerShell", value: 31 }, { label: "Infrastructure overlap", value: 24 },
    { label: "T1547.001 Registry Run Keys", value: 19 }, { label: "Artifact overlap", value: 16 },
    { label: "Temporal similarity", value: 10 }] },
  { name: "APT28", alias: "Fancy Bear", origin: "Russia", confidence: 68.9, tone: "t2", evidence: [
    { label: "T1059.001 PowerShell", value: 28 }, { label: "Infrastructure overlap", value: 21 },
    { label: "T1003 OS Credential Dumping", value: 20 }, { label: "Malware family proximity", value: 17 },
    { label: "Temporal similarity", value: 14 }] },
  { name: "Lazarus Group", alias: "Hidden Cobra", origin: "North Korea", confidence: 42.1, tone: "t3", evidence: [
    { label: "T1566.001 Spearphishing", value: 27 }, { label: "Shared compiler metadata", value: 23 },
    { label: "T1055 Process Injection", value: 20 }, { label: "Infrastructure overlap", value: 18 },
    { label: "Temporal similarity", value: 12 }] },
  { name: "Turla", alias: "Venomous Bear", origin: "Russia", confidence: 31.7, tone: "t4", evidence: [
    { label: "DNS behaviour overlap", value: 26 }, { label: "T1071.004 DNS", value: 22 },
    { label: "Victimology", value: 20 }, { label: "Toolchain similarity", value: 18 },
    { label: "Temporal similarity", value: 14 }] },
];
