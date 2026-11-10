// Client-side upload checks (the server checks everything again).
export const ACCEPTED_EXTENSIONS = [".pdf", ".txt", ".md", ".html", ".htm", ".docx", ".json"] as const;
export const ACCEPT_ATTR = ".pdf,.txt,.md,.html,.htm,.docx,.json";
export const MAX_UPLOAD_MB = 20;

export interface UploadInput { file: File | null; incidentName: string }

/** Returns a map of field -> message; empty when the input is valid. */
export function validateUpload({ file, incidentName }: UploadInput): Partial<Record<"file" | "incidentName", string>> {
  const errors: Partial<Record<"file" | "incidentName", string>> = {};
  if (!incidentName.trim()) errors.incidentName = "Give the incident a name.";
  else if (incidentName.length > 200) errors.incidentName = "Keep the name under 200 characters.";
  if (!file) {
    errors.file = "Choose a report file.";
  } else {
    const ext = file.name.includes(".") ? file.name.slice(file.name.lastIndexOf(".")).toLowerCase() : "";
    if (!(ACCEPTED_EXTENSIONS as readonly string[]).includes(ext)) {
      errors.file = `"${ext || file.name}" files are not supported. Use PDF, TXT, MD, HTML, DOCX or STIX JSON.`;
    } else if (file.size === 0) {
      errors.file = "The file is empty.";
    } else if (file.size > MAX_UPLOAD_MB * 1024 * 1024) {
      errors.file = `The file is ${(file.size / 1024 / 1024).toFixed(1)} MB; the limit is ${MAX_UPLOAD_MB} MB.`;
    }
  }
  return errors;
}

export function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
