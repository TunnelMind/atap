// Draws verifyZip's view. Every string here may come from a hostile ZIP, so
// the DOM is built with createElement and textContent only: no receipt string is ever
// parsed as HTML.
// `doc` is anything with createElement (the page's document, or a stub in a
// DOM-free test) whose elements have textContent, className, appendChild.

export const NO_ED25519 =
  "This browser can't verify Ed25519 signatures, so it can't check this receipt. " +
  'Use a current Chrome, Edge, Firefox or Safari, or the atap-witness CLI.'

export function render(doc, view) {
  const el = (tag, text, cls) => {
    const e = doc.createElement(tag)
    if (text !== undefined) e.textContent = String(text)
    if (cls) e.className = cls
    return e
  }
  const add = (parent, ...kids) => {
    for (const k of kids) parent.appendChild(k)
    return parent
  }
  const root = el('div')
  if (view.status === 'no-ed25519') return add(root, el('p', NO_ED25519, 'notice'))
  if (view.status === 'error') return add(root, el('p', `Could not read this ZIP: ${view.reason}`, 'notice'))

  const { result } = view
  add(root, el('p', result.ok ? 'Verified: yes' : 'Verified: no', result.ok ? 'verdict ok' : 'verdict bad'))
  // A receipt that fails says nothing we can rely on, so only the reason shows.
  if (!result.ok) return add(root, el('p', `Reason: ${result.reason}`))

  const { receipt, ait, events } = view
  const dl = el('dl')
  const row = (k, v, cls) => add(dl, el('dt', k), el('dd', v ?? '—', cls))
  const witness = String(receipt.witness)
  row('Witness', `${witness} (${witness.startsWith('did:key:') ? 'did:key' : 'OAI'})`, 'hash')
  row('Operator', ait.operator, 'hash')
  row('Attestation strength', result.attestation_strength)
  row('Profile', receipt.profile)
  row('AIT', receipt.ait, 'hash')
  row('Receipt', receipt.id, 'hash')
  row('Period', `${receipt.period_start} – ${receipt.period_end}`)
  row('Blocks', result.blocks)
  row('Events', events.length)
  row('Chain head hash', receipt.chain_head_hash, 'hash')
  add(root, dl)

  if (result.warnings?.length) {
    add(root, el('h2', 'Warnings'), add(el('ul'), ...result.warnings.map(w => el('li', w))))
  }

  // The tier is the profile's payload.evidence (asserted / anchored / witnessed).
  add(root, el('h2', 'Events'))
  const ol = add(root, el('ol', undefined, 'events'))
  for (const e of events) {
    add(
      ol,
      add(
        el('li'),
        el('span', e.event_type, 'type'),
        el('span', e.payload?.evidence ?? 'no tier', 'tier'),
        el('span', e.witnessed_at, 'time'),
      ),
    )
  }

  add(root, el('h2', 'Files'))
  const files = add(root, el('ul', undefined, 'files'))
  for (const f of receipt.files ?? []) {
    add(files, add(el('li'), el('span', f.path), el('span', f.sha256 ?? '(not hashed)', 'hash')))
  }
  return root
}
