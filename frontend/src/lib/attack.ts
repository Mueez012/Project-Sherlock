import catalog from "@/data/attack-catalog.json";

// The 14 ATT&CK v14 Enterprise tactics in kill-chain order.
export const ATTACK_TACTICS = [
  { id: "TA0043", name: "Reconnaissance" },
  { id: "TA0042", name: "Resource Development" },
  { id: "TA0001", name: "Initial Access" },
  { id: "TA0002", name: "Execution" },
  { id: "TA0003", name: "Persistence" },
  { id: "TA0004", name: "Privilege Escalation" },
  { id: "TA0005", name: "Defense Evasion" },
  { id: "TA0006", name: "Credential Access" },
  { id: "TA0007", name: "Discovery" },
  { id: "TA0008", name: "Lateral Movement" },
  { id: "TA0009", name: "Collection" },
  { id: "TA0011", name: "Command and Control" },
  { id: "TA0010", name: "Exfiltration" },
  { id: "TA0040", name: "Impact" },
] as const;

export const TACTIC_NAME: Record<string, string> = Object.fromEntries(ATTACK_TACTICS.map((t) => [t.id, t.name]));

/** Kill-chain position (1 to 14), name and link of each tactic, from the bundled catalog. */
export const TACTIC_INFO: Record<string, { name: string; order: number; url: string }> = Object.fromEntries(
  catalog.tactics.map((t) => [t.id, { name: t.name, order: t.order, url: t.url }]),
);

export interface CatalogTechnique {
  id: string;
  name: string;
  tactic_ids: string[];
  url: string;
}

/** The 189 parent techniques of the label space, with their tactics and links (src/data/attack-catalog.json,
 * the same 203 labels as the D1 dataset). */
export const TECHNIQUE: Record<string, CatalogTechnique> = Object.fromEntries(
  catalog.techniques.map((t) => [t.id, t]),
);
