type EvidenceState = "VERIFIED_HOST_ONLY" | "BLOCKED";

interface EvidenceCase {
  id: string;
  title: string;
  state: EvidenceState;
  statusLabel: string;
  summary: string;
  command: string;
  evidence: string[];
  proves: string;
  doesNotProve: string;
}

const cases: EvidenceCase[] = [
  {
    id: "C01",
    title: "Real host build succeeds",
    state: "VERIFIED_HOST_ONLY",
    statusLabel: "VERIFIED HOST ONLY",
    summary: "A real compiler produced an artifact that FUNES captured and the independent verifier accepted.",
    command: "make test",
    evidence: ["source state", "argv and exit status", "artifact SHA-256", "offline verifier"],
    proves: "The recorded host build and bundle are internally consistent.",
    doesNotProve: "A QNX target build or software safety.",
  },
  {
    id: "C03",
    title: "Real test failure is preserved",
    state: "VERIFIED_HOST_ONLY",
    statusLabel: "VERIFIED HOST ONLY",
    summary: "The fixture's real failing path returns exit code 3 and remains visible as evidence instead of being laundered into success.",
    command: "qnx8-hello fail",
    evidence: ["test argv", "artifact association", "exit code 3", "captured stdout/stderr"],
    proves: "FUNES records an observed failure without destroying the valid bundle.",
    doesNotProve: "That every test passed or that coverage is complete.",
  },
  {
    id: "C05",
    title: "Real bundle mutation is rejected",
    state: "VERIFIED_HOST_ONLY",
    statusLabel: "VERIFIED HOST ONLY",
    summary: "A disposable copy of a real bundle is changed by one byte and the verifier names the resulting mismatch.",
    command: "funes-verify mutated-bundle",
    evidence: ["original bundle", "disposable mutation", "DIGEST_MISMATCH", "non-zero verifier exit"],
    proves: "The verifier detects post-capture changes to recorded bytes.",
    doesNotProve: "That the original producer or host was honest.",
  },
  {
    id: "C08",
    title: "Real QNX build",
    state: "BLOCKED",
    statusLabel: "BLOCKED",
    summary: "The real-SDP smoke runner is ready, but this host still lacks a running qcc environment.",
    command: "make qnx-smoke QNX_TARGET_FLAGS='-V<validated-target>'",
    evidence: ["licensed SDP required", "QNX_HOST required", "QNX_TARGET required", "explicit target flags required"],
    proves: "Nothing yet: this case is honestly waiting for the SDK environment.",
    doesNotProve: "Any QNX result; the fake-qcc contract harness is not QNX evidence.",
  },
];

function requireElement<T extends Element>(selector: string): T {
  const element = document.querySelector<T>(selector);
  if (!element) {
    throw new Error(`Minimal evidence UI markup is incomplete: ${selector}`);
  }
  return element;
}

const caseSelect = requireElement<HTMLSelectElement>("#case-select");
const caseTitle = requireElement<HTMLElement>("#case-title");
const caseSummary = requireElement<HTMLElement>("#case-summary");
const caseStatus = requireElement<HTMLElement>("#case-status");
const caseCommand = requireElement<HTMLElement>("#case-command");
const caseEvidence = requireElement<HTMLUListElement>("#case-evidence");
const caseProves = requireElement<HTMLElement>("#case-proves");
const caseDoesNotProve = requireElement<HTMLElement>("#case-does-not-prove");

for (const evidenceCase of cases) {
  const option = document.createElement("option");
  option.value = evidenceCase.id;
  option.textContent = `${evidenceCase.id} · ${evidenceCase.title}`;
  caseSelect.append(option);
}

function renderCase(id: string): void {
  const evidenceCase = cases.find((candidate) => candidate.id === id) ?? cases[0];
  caseTitle.textContent = evidenceCase.title;
  caseSummary.textContent = evidenceCase.summary;
  caseStatus.textContent = evidenceCase.statusLabel;
  caseStatus.dataset.state = evidenceCase.state;
  caseCommand.textContent = evidenceCase.command;
  caseProves.textContent = evidenceCase.proves;
  caseDoesNotProve.textContent = evidenceCase.doesNotProve;
  caseEvidence.replaceChildren(
    ...evidenceCase.evidence.map((item) => {
      const listItem = document.createElement("li");
      listItem.textContent = item;
      return listItem;
    }),
  );
}

caseSelect.addEventListener("change", () => renderCase(caseSelect.value));
renderCase(cases[0].id);
