# CoFi — Collaborative Finance

## What is CoFi

CoFi is a protocol for **on-chain organizations** — projects, businesses, and any endeavour where people come together to do work.

The central idea: contributors earn a share of an organization's wealth proportional to their contributions. Contributions can be labor, capital, or any other form of value the org recognizes. What matters is that **all contributions are treated equally under one model** — the charter defines how each type is valued relative to the others.

## The Core Differentiator

Most attempts at decentralized organizations (DAOs) replicate financial capital structures on-chain — governance power flows from tokens held, not work done. You buy in, not contribute in.

CoFi is different:

| DAOs (typically) | CoFi |
|---|---|
| Governance power = tokens held | Governance power = contributions made |
| Capital has automatic dominance | Capital is one contribution type among many |
| You buy in | You contribute in |
| Capital-weighted | **Contribution-weighted** |

CoFi is a **contribution-weighted cooperative, enforced by code.** Labor and capital both have a place — the charter decides their relative value. Neither has automatic dominance.

On-chain means: rules are in the contract, assets are in the contract, math is verifiable by anyone. Enforcement is trustless. The honest caveat: the contribution input layer requires human validation — off-chain work has to meet on-chain record somewhere. Enforcement is fully on-chain. The full stack isn't.

---

## Entities

| Entity | Purpose |
|---|---|
| **Organization** | The container. Has a charter, an asset pool, and members. Can be one person or many. |
| **Charter** | The constitution of an org. Defines skill multipliers, validation rules, redemption rules, membership model. Set at creation, amendable by governance. |
| **Contributor** | A member of an org. Has a profile: skills, seniority, reputation. Can belong to multiple orgs simultaneously. |
| **Contribution** | A unit of work submitted by a contributor. Has a type, units, skill category, and a status: `pending → accepted / rejected / disputed`. |
| **Share** | A contributor's proportional claim on the org's assets. Derived, not stored: `sum(contributor's weighted contributions) / sum(all weighted contributions)`. |
| **Asset Pool** | The org's holdings. Initially fungible assets only (ETH, stablecoins, etc.). Future: tokenized diverse assets. |
| **Validation** | The review and approval process for pending contributions. Governed by the charter. |
| **Validator** | A CoFi org (including single-person orgs) that participates in chain consensus. Consensus weight derives from contribution score, not stake. |

---

## Contribution Types

CoFi recognizes two classes of contribution:

### Labor contributions
Work done for the org: engineering, design, writing, management, operations, etc. Submitted by contributors, validated by peers.

### Capital contributions
Monetary investment in the org. Treated as a contribution like any other — the charter defines the conversion rate from currency units to contribution points.

```
Contribution Value (capital) = amount × capital_rate
```

Where `capital_rate` is set in the charter (e.g. 1 ETH = 500 contribution points). Investors become contributors. No special class, no special rights — they play by the same rules as everyone else.

### Safeguards against capital dominance

Capital contributions are instantaneous and can be large. Without bounds, a single investor could acquire a dominant share in one transaction, recreating capital-weighted governance through the back door. The charter must define at least one of:

| Safeguard | Description |
|---|---|
| **Capital cap** | Monetary contributions cannot exceed X% of total weighted contributions. Beyond the cap, additional capital earns no shares. |
| **Capital vesting** | Capital contributions unlock gradually over time, preventing instant dominance. |
| **Diminishing returns** | The conversion rate decreases as more capital accumulates — early capital is worth more per point than later capital. |
| **Labor-first window** | For the first N days, only labor contributions are accepted. Capital opens after a labor baseline is established. |

The capital cap is the most important of these. Without it, the contribution-weighted model can be legally respected while being practically overridden by money.

---

## Contribution Valuation

Every labor contribution gets a weighted score:

```
Contribution Value = units × base_rate × skill_multiplier × seniority_multiplier × reputation_multiplier × scarcity_multiplier
```

| Multiplier | Description |
|---|---|
| **base_rate** | Everyone starts equal (e.g. 1). |
| **skill_multiplier** | Defined in the charter per skill (e.g. engineer: 1.6, designer: 1.5, PM: 1.6, doc writer: 1.2). |
| **seniority_multiplier** | Increases with time as a member of the org. Rewards loyalty and institutional knowledge. |
| **reputation_multiplier** | Increases when peers rate contributions highly. Rewards quality, not just quantity. |
| **scarcity_multiplier** | Dynamic. Reflects how much the org currently needs a particular skill. Incentivizes filling gaps. |

---

## Share Calculation

```
Share(A) = sum(A's weighted contributions) / sum(all weighted contributions)
```

The charter can optionally define equity dilution mechanics (e.g. early contributions worth more), but it is not mandatory.

---

## Contribution Validation

Contributions enter a tiered review process:

1. **Self-reported + peer review**: contributor logs work → enters `pending` → N of M reviewers approve → `accepted`. Uncontested contributions auto-accept after a charter-defined timeout (e.g. 7 days).
2. **Reputation-weighted validation**: reviewer weight is proportional to their own reputation score. Good contributors become good validators. Intentionally circular by design.
3. **Dispute mechanism**: any member can flag a contribution within the review window → flagged contributions escalate to a broader community vote.

The charter defines: review window duration, number of approvers required, dispute threshold.

---

## Redemption

Contributors can redeem (burn) their shares at any time in exchange for their proportional slice of the asset pool.

Example: org has 100 ETH, contributor B holds 25% share → B redeems → receives 25 ETH → remaining contributors share 75 ETH.

### Redemption safeguards (all charter-defined, all optional)

| Safeguard | Description |
|---|---|
| **Vesting period** | Contributions only become redeemable after X days. |
| **Redemption cap** | Max Y% of assets redeemable per time period. Prevents bank runs. |
| **Exit tax** | Small % of redeemed value stays in the pool, compensating remaining members. |
| **Project lock-in** | Contributions tied to an active project can't be redeemed until it completes. |

---

## Membership

- Default: open. Anyone can join and submit contributions.
- Charter can restrict membership (permissioned model).
- In practice, the contribution validation process is the real gating mechanism — the acceptance of work, not the acceptance of members.

### Single-person organizations

There is no minimum member requirement. A CoFi org can be one person.

This is not a edge case — it's a first-class design decision with real implications:

- **Validators**: individual contributors can run validator nodes as single-person orgs (see Chain Architecture).
- **Freelancers**: a single-person org lets any individual maintain a portable, on-chain contribution record across clients and projects.
- **Proof-of-work résumé**: because contribution scores live on-chain, a contributor's history across all orgs they've ever belonged to is verifiable by anyone. Not "I claim I did X" — "the chain shows I did X, it was validated by Y people, and it earned Z score." Professional reputation becomes portable and unforgeable.

---

## Funding CoFi

CoFi is itself funded using the CoFi model. There is no separate investor class.

- All work done to build CoFi (code, design, documentation, community) is logged as labor contributions to the CoFi Protocol Organization
- Investors who fund the protocol's development contribute capital — logged as capital contributions at a charter-defined rate
- Everyone — builders and investors alike — holds shares in the Protocol Org proportional to their total contributions
- When the protocol generates fee revenue, all contributors redeem proportionally

This means CoFi's development is the **first real proof that the model works**. When the protocol launches, it was itself built using CoFi.

### Funding strategy (phased)

| Phase | Source | Rationale |
|---|---|---|
| **Bootstrap** | Founder runway + grants | Non-dilutive. Grants available from Ethereum Foundation, Cosmos ecosystem, Gitcoin, Protocol Labs. |
| **Growth** | Capital contributions to Protocol Org | Investors become contributors. No equity, no board seats, no exit pressure. |
| **Sustaining** | Protocol fee revenue | Redemptions from the Protocol Org asset pool. Self-sustaining once adoption reaches scale. |

### ⚠ Regulatory note

Accepting capital in exchange for a proportional claim on future asset pool value may constitute a **securities offering** in many jurisdictions, regardless of how it is structured. This requires legal counsel before any capital contributions are accepted. Potential structures to explore: utility tokens, cooperative membership, jurisdiction-specific frameworks (e.g. Wyoming DAO LLC, EU cooperative law).

---

## Monetization

CoFi is free to use beyond on-chain transaction costs. Revenue is generated at two moments:

| Fee type | Description |
|---|---|
| **Org creation fee** | One-time fee to deploy a new organization. A commitment signal — serious orgs will pay it. |
| **Redemption fee** | Small % cut on every withdrawal. Proportional to actual value flowing through the protocol. |

- Percentages are **protocol-defined bounds** (e.g. max 3%)
- Each org sets its own fee within those bounds (e.g. 0–3%), allowing orgs to compete on terms
- No fees on day-to-day activity: contribution logging, validation, share calculation

### Protocol treasury: CoFi governs CoFi

All protocol fees flow into the **CoFi Protocol Organization** — a CoFi org that is itself governed by CoFi rules. The protocol is its own first customer.

- Founder(s) start with a large share by virtue of building it
- Future contributors (developers, designers, community managers) earn shares too
- Protocol fee revenue is the asset pool
- Anyone who contributed to CoFi can redeem proportionally

This is philosophically coherent: the same model that powers every other org on the chain also powers the chain itself.

---

## Chain Architecture

CoFi runs on a **purpose-built custom L1 blockchain**, optimized for high-frequency, small-value transactions with a UX-first design.

### Why a custom chain

- Full independence — not subject to another chain's constraints, upgrades, or politics
- Full control over the execution environment: gas model, account abstraction, custom precompiles
- Optimized for CoFi's specific transaction patterns: contribution logging, validation votes, reputation updates — frequent and small
- Enables contribution-weighted consensus (see below), which is impossible as a guest on another chain

### Technology stack (phased)

| Phase | Consensus | VM | Focus |
|---|---|---|---|
| **1** | CometBFT | EVM-compatible | Prove the protocol works |
| **2** | CometBFT | Custom CoFi VM | Optimize UX and gas for CoFi operations |
| **3** | Contribution-weighted BFT | Custom CoFi VM | Full philosophical coherence |

- **P2P**: CometBFT built-in (Phase 1) → libp2p for finer control (Phase 2+)
- **Application layer**: Cosmos SDK modules for CoFi logic throughout

### Contribution-weighted consensus

In Phase 3, validators are CoFi orgs whose consensus weight derives from their contribution scores — not from staked capital.

```
Consensus weight(V) = contribution_score(V) / sum(contribution_scores of all validators)
Safety rule: 2/3 of total weight must agree for finality (BFT)
```

Block production is itself logged as a contribution to the CoFi Protocol Organization:

- Produce valid blocks → earn contributions → gain consensus weight → more influence
- Misbehave or go offline → slashing → contributions reduced → lose weight

This means the consensus layer and the application layer share the same underlying model. **CoFi's security is enforced by the same mechanism CoFi uses to govern organizations.**

### Validator bootstrap

The circular dependency (need validators to run the chain; need the chain to record contributions) is resolved in three phases:

**Pre-genesis** — All work done to build CoFi (code, design, documentation, testing) is tracked off-chain in a verifiable, signed ledger. This forms the initial contribution graph of the CoFi Protocol Organization before the chain exists.

**Genesis** — Initial validators are the top contributors to the protocol org. Each starts with their pre-genesis contribution score as their consensus weight. A minimum stake floor provides Sybil resistance. This floor decreases on a published schedule as the on-chain contribution graph matures.

**Post-genesis** — New validators accumulate contribution scores first, then meet the declining stake floor. Block production earns ongoing contributions. The stake floor eventually becomes negligible; contribution score is the only meaningful entry requirement.

---

## Use Cases

| Use case | Description |
|---|---|
| **Project team** | A group of contributors building something together. Share revenue proportionally to contributions. |
| **Open source project** | Anyone can contribute. Accepted contributions earn shares of any donations or revenue. |
| **Freelancer / solo** | Single-person org as a portable professional identity and contribution record. |
| **Agency / collective** | Multiple contributors serving clients. Revenue distributed by contribution weight. |
| **Funded startup** | Investors contribute capital, builders contribute labor. Charter defines relative value. No separate equity class. |
| **Validator node** | Single-person or small-team org running chain infrastructure. Earns contributions via block production. |
| **The protocol itself** | CoFi Protocol Organization. Funded by protocol fees and capital contributions. Governed by all contributors — builders and investors alike. |

---

## Backlog

### Concept
- Charter structure in detail (fields, defaults, amendment process)
- Capital rate: how is the ETH → contribution points conversion rate determined and updated
- Capital cap: default value, whether it can be zero (labor-only orgs) or 100% (capital-only)
- Seniority multiplier: exact scaling function
- Reputation score mechanics: how peer ratings accumulate and decay
- Scarcity multiplier: who adjusts it, how often, by what mechanism
- Governance: how the charter itself gets amended
- Custom consensus protocol: formal design of contribution-weighted BFT

### Legal
- Regulatory classification of capital contributions (securities law)
- Jurisdiction analysis: Wyoming DAO LLC, EU cooperative law, others
- Structure for accepting capital contributions legally before protocol launch

### Technical
- Cosmos SDK module architecture for CoFi logic
- Custom VM specification (Phase 2)
- Off-chain layer: indexing, UI, validation coordination
- Tokenized non-fungible / diverse assets (Phase 2+)
- Stake floor decay schedule
- Slashing conditions and their effect on contribution score
- Multi-org contributor identity and aggregation

### Product
- User journey: creating an org, joining, submitting a contribution, redeeming
- Onboarding and charter templates for common org types
- Validator onboarding flow
- Portable identity / proof-of-work résumé UI
