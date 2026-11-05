const consolePanel = document.querySelector('[data-console]');
const mutateButton = document.querySelector('[data-mutate]');
const resetButton = document.querySelector('[data-reset]');
const verdictLabel = document.querySelector('[data-verdict-label]');
const verdictCopy = document.querySelector('[data-verdict-copy]');
const artifactState = document.querySelector('[data-artifact-state]');
const hash = document.querySelector('[data-hash]');
const command = document.querySelector('[data-command]');
const demoVideo = document.querySelector('[data-demo-video]');
const videoPlaceholder = document.querySelector('.video-placeholder');

function showMutation() {
  consolePanel.classList.add('is-breached');
  verdictLabel.textContent = 'DIGEST_MISMATCH';
  verdictCopy.textContent = 'Artifact digest diverged from the sealed manifest after a one-byte mutation.';
  artifactState.textContent = 'MISMATCH';
  hash.textContent = '5ca2…67fd0ba7X';
  command.textContent = 'funes-verify evidence.bundle  →  exit 3';
  mutateButton.hidden = true;
  resetButton.hidden = false;
}

function resetEvidence() {
  consolePanel.classList.remove('is-breached');
  verdictLabel.textContent = 'INTEGRITY_VALID';
  verdictCopy.textContent = 'Every recorded blob still matches the sealed manifest.';
  artifactState.textContent = 'VALID';
  hash.textContent = '5ca2…67fd0ba72';
  command.textContent = 'funes-verify evidence.bundle';
  mutateButton.hidden = false;
  resetButton.hidden = true;
}

mutateButton.addEventListener('click', showMutation);
resetButton.addEventListener('click', resetEvidence);

demoVideo.addEventListener('canplay', () => {
  demoVideo.hidden = false;
  videoPlaceholder.hidden = true;
});
