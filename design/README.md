# Remotino UI design system

The design deliverable from the design app. **Source of truth for the Phase 3
Svelte shell.** Do not hand-edit the `.dc.html` files - re-open them in the
design app to change them, then re-export here.

## Files

| File | What |
|---|---|
| `Remotino.dc.html` | The interactive shell: unlock, connections tree, tabs, command palette, add/edit modal, admin, and every security state |
| `Connections Variations.dc.html` | Density/row-height variations of the tree |
| `Design Tokens.dc.html` | The token spec: colours (dark + light), type, spacing, radii |
| `support.js` | The design-app runtime that hydrates the `.dc.html` files |
| `preview.png` | Thumbnail |

## Translating to Svelte

The mockups use the design app's DSL, which maps almost 1:1 to Svelte:

| Design DSL | Svelte |
|---|---|
| `{{ x }}` | `{x}` |
| `<sc-if value="{{ c }}">` | `{#if c}` |
| `<sc-for list="{{ xs }}" as="x">` | `{#each xs as x}` |
| `onClick="{{ h }}"` | `on:click={h}` |
| `style-focus="..."` | `:focus { ... }` in `<style>` |
| `style-hover="..."` | `:hover { ... }` |

Every inline style uses the CSS custom properties from `Design Tokens.dc.html`,
so the token block lifts straight into a global stylesheet and the components
reference `var(--bg)`, `var(--rdp)`, `var(--row-h)`, etc. unchanged.

## Tokens (dark; light overrides under `[data-theme="light"]`)

Backgrounds `--bg #0b0d0f` / `--bg-2 #111417` / `--bg-3 #191d21` /
`--bg-inset #08090a`. Borders `--border #20262b` / `--border-2 #2b3237`.
Text `--text #dfe4e8` / `--text-dim #98a2ab` / `--text-mute #616b73`.
Accent (SSH) `--accent #3fd07d`; `--ssh` aliases it. RDP `--rdp #5aa2e0`.
Status `--ok` `--warn #e0a83f` `--err #e05d5d`. Row height `--row-h 22px`.
Mono and UI font stacks in `--mono` / `--ui`.

## Not in the mockup (deferred, Phase 6)

Escrow admin (quorum setup, recovery ceremony) and the Deactivation-Reactivation
niceties. The primitives exist in `remotino-crypto`; the admin UI for them comes
with the rest of Phase 6.
