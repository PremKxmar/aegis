"""Knowledge graph — the domain facts policy rules are written *about*.

Why this exists
---------------
Two of this project's own red-team findings were, in hindsight, missing graph
queries rather than missing rules:

  ATT-09/ATT-13  mail walked out to collector@evil-exfil.test. Every rule in
                 `40-comms.yaml` governed *whether* mail could be sent; none
                 governed *to whom*. The fix -- `allowed_recipients` in
                 `SessionState` -- is a hand-rolled one-hop traversal:
                 "customer --HAS_EMAIL--> address".

  ATT-18        (added with this module) money moves to an account that has
                 nothing to do with the ticket being worked. No per-call rule
                 can see that, because both the account and the amount are
                 individually legitimate. It is a *relationship* question.

Writing those relationships down as a graph does two jobs:

  runtime   `kg.*` facts let a rule ask "is this recipient related to the
            customer on this ticket?" instead of consulting a set that
            somebody has to remember to populate.

  offline   `policygen.py` walks the same graph to enumerate paths that
            *should* be impossible, probes the live governor for each, and
            proposes a rule wherever the stack says yes. That is the answer to
            "sometimes the person doesn't know what rules to check": the
            graph knows which questions exist, so it can find the rules a
            human forgot to write.

Structure: (subject, predicate, object) triples over namespaced node ids
(`customer:C-1001`, `class:pii`, `tool:send_email`). Namespacing keeps the id
space unambiguous when a customer id and a ticket id could otherwise collide,
and makes a path printable as evidence in an audit record.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Iterable

from .domain import Sensitivity
from .procedure import EDGES as PROC_EDGES, NODES as PROC_NODES
from .tools.banking import SPECS, BankState, seed_bank


@dataclass(frozen=True)
class Triple:
    subject: str
    predicate: str
    object: str

    def to_dict(self) -> dict[str, str]:
        return {"s": self.subject, "p": self.predicate, "o": self.object}

    def __str__(self) -> str:
        return f"{self.subject} --{self.predicate}--> {self.object}"


# Predicate vocabulary. Kept small on purpose: every predicate here is one a
# policy rule or the generator actually traverses. A graph full of relations
# nothing queries is documentation, not enforcement.
HAS_EMAIL = "HAS_EMAIL"
HAS_DATA = "HAS_DATA"
CLASSIFIED_AS = "CLASSIFIED_AS"
ABOUT = "ABOUT"
READS_CLASS = "READS_CLASS"
WRITES_CLASS = "WRITES_CLASS"
EGRESSES_TO = "EGRESSES_TO"
REQUIRES_CAP = "REQUIRES_CAP"
HOLDS_CAP = "HOLDS_CAP"
IN_RING = "IN_RING"
COMPLETES = "COMPLETES"
PRECEDES = "PRECEDES"

EXTERNAL = "zone:external"


class KnowledgeGraph:
    """Triple store with the handful of queries this project needs.

    Deliberately not a graph database. Four customers and six tools do not
    need one, and an in-process dict keeps the governor's hot path free of a
    network round trip -- the whole argument for deterministic governance is
    that it costs microseconds.
    """

    def __init__(self, triples: Iterable[Triple] | None = None) -> None:
        self._triples: list[Triple] = list(triples or [])
        self._out: dict[str, list[Triple]] = {}
        self._in: dict[str, list[Triple]] = {}
        for t in self._triples:
            self._index(t)

    def _index(self, t: Triple) -> None:
        self._out.setdefault(t.subject, []).append(t)
        self._in.setdefault(t.object, []).append(t)

    def add(self, subject: str, predicate: str, obj: str) -> None:
        t = Triple(subject, predicate, obj)
        self._triples.append(t)
        self._index(t)

    # ── traversal ───────────────────────────────────────────────────

    def out(self, node: str, predicate: str | None = None) -> list[Triple]:
        rows = self._out.get(node, [])
        return [t for t in rows if predicate is None or t.predicate == predicate]

    def into(self, node: str, predicate: str | None = None) -> list[Triple]:
        rows = self._in.get(node, [])
        return [t for t in rows if predicate is None or t.predicate == predicate]

    def objects(self, node: str, predicate: str) -> list[str]:
        return [t.object for t in self.out(node, predicate)]

    def subjects(self, node: str, predicate: str) -> list[str]:
        return [t.subject for t in self.into(node, predicate)]

    def path(self, src: str, dst: str, max_hops: int = 4) -> list[Triple] | None:
        """Shortest undirected path, or None.

        Undirected because relatedness is symmetric for our purposes: an
        address belongs to a customer whether you walk HAS_EMAIL forwards or
        backwards. The returned triples keep their original direction so the
        path still reads correctly as evidence.
        """
        if src == dst:
            return []
        seen = {src}
        queue: deque[tuple[str, list[Triple]]] = deque([(src, [])])
        while queue:
            node, trail = queue.popleft()
            if len(trail) >= max_hops:
                continue
            for t in self.out(node) + self.into(node):
                nxt = t.object if t.subject == node else t.subject
                if nxt in seen:
                    continue
                path = trail + [t]
                if nxt == dst:
                    return path
                seen.add(nxt)
                queue.append((nxt, path))
        return None

    def related(self, src: str, dst: str, max_hops: int = 2) -> bool:
        return self.path(src, dst, max_hops) is not None

    # ── domain queries ──────────────────────────────────────────────

    def customer_of_email(self, email: str) -> str:
        """Which customer owns this address, '' if nobody in the graph does."""
        if not email:
            return ""
        owners = self.subjects(f"email:{email}", HAS_EMAIL)
        return owners[0].split(":", 1)[1] if owners else ""

    def customer_of_ticket(self, ticket_id: str) -> str:
        if not ticket_id:
            return ""
        subs = self.objects(f"ticket:{ticket_id}", ABOUT)
        return subs[0].split(":", 1)[1] if subs else ""

    def emails_of_customer(self, customer_id: str) -> list[str]:
        if not customer_id:
            return []
        return [o.split(":", 1)[1]
                for o in self.objects(f"customer:{customer_id}", HAS_EMAIL)]

    def classes_read_by(self, tool: str) -> list[str]:
        return [o.split(":", 1)[1] for o in self.objects(f"tool:{tool}", READS_CLASS)]

    def sensitive_tools(self) -> list[str]:
        """Tools that touch a restricted class or leave the boundary."""
        out = set()
        for t in self._triples:
            if t.predicate == READS_CLASS and t.object in ("class:pii", "class:pci"):
                out.add(t.subject.split(":", 1)[1])
            if t.predicate == EGRESSES_TO:
                out.add(t.subject.split(":", 1)[1])
        return sorted(out)

    def egress_tools(self) -> list[str]:
        return sorted(t.subject.split(":", 1)[1]
                      for t in self._triples if t.predicate == EGRESSES_TO)

    def mutating_tools(self) -> list[str]:
        return sorted({t.subject.split(":", 1)[1]
                       for t in self._triples if t.predicate == WRITES_CLASS})

    def customers(self) -> list[str]:
        return sorted({t.subject.split(":", 1)[1] for t in self._triples
                       if t.subject.startswith("customer:")})

    def tickets(self) -> list[str]:
        return sorted({t.subject.split(":", 1)[1] for t in self._triples
                       if t.subject.startswith("ticket:")})

    # ── the policy-context facts ────────────────────────────────────

    def context(self, tool: str, args: dict[str, Any],
                subject_customer: str = "") -> dict[str, Any]:
        """Flatten graph answers into the `kg.*` vocabulary policy reads.

        `subject_customer` is the customer this session legitimately
        established a claim on -- the one named by the *ticket*, not one named
        in its body. Every relatedness question is asked relative to that
        anchor; without an anchor the graph has nothing to compare against and
        the facts stay false so these rules simply do not fire.

        As everywhere else in this project, negatives are pre-computed into
        positive booleans because the condition language cannot express `not`.
        """
        spec = SPECS.get(tool)
        recipient = str(args.get("to", "") or "")
        target = str(args.get("customer_id", "") or "")

        recipient_owner = self.customer_of_email(recipient) if recipient else ""
        is_egress = bool(spec and spec.egress)

        # Unrelated recipient: an egress call whose destination the graph
        # cannot link back to this session's subject. An address that belongs
        # to *some* customer but not *this* one is still unrelated -- that is
        # the cross-customer leak ATT-13 aimed at.
        recipient_unrelated = bool(
            is_egress and recipient
            and (not recipient_owner
                 or (subject_customer and recipient_owner != subject_customer))
        )

        # Subject mismatch: acting on a customer other than the one the ticket
        # is about. Only meaningful once a ticket anchors the session.
        subject_mismatch = bool(
            subject_customer and target and target != subject_customer
        )

        hops = -1
        if subject_customer and recipient:
            p = self.path(f"customer:{subject_customer}", f"email:{recipient}", 3)
            hops = len(p) if p is not None else -1

        return {
            "subject": subject_customer or "none",
            "subject_known": bool(subject_customer),
            "subject_mismatch": subject_mismatch,
            "subject_matches": bool(subject_customer and target
                                    and target == subject_customer),
            "recipient": recipient or "none",
            "recipient_owner": recipient_owner or "none",
            "recipient_known": bool(recipient_owner),
            "recipient_unknown": bool(is_egress and recipient and not recipient_owner),
            "recipient_unrelated": recipient_unrelated,
            "recipient_related": bool(is_egress and recipient
                                      and not recipient_unrelated),
            "hops_to_recipient": hops,
            "reads_restricted": bool(
                set(self.classes_read_by(tool)) & {"pii", "pci"}),
        }

    # ── introspection ───────────────────────────────────────────────

    def triples(self) -> list[Triple]:
        return list(self._triples)

    def stats(self) -> dict[str, Any]:
        by_pred: dict[str, int] = {}
        for t in self._triples:
            by_pred[t.predicate] = by_pred.get(t.predicate, 0) + 1
        nodes = {t.subject for t in self._triples} | {t.object for t in self._triples}
        return {"triples": len(self._triples), "nodes": len(nodes),
                "predicates": by_pred}

    def to_dict(self) -> dict[str, Any]:
        return {"triples": [t.to_dict() for t in self._triples],
                "stats": self.stats()}


# ── construction ────────────────────────────────────────────────────

def build_graph(state: BankState | None = None,
                registry: Any = None) -> KnowledgeGraph:
    """Derive the graph from live system state, never from a static fixture.

    Everything here is read out of the objects the running system already
    holds -- the bank's records, the tool specs, the agent registry, the
    procedure graph. A hand-maintained copy would drift, and a drifted
    knowledge graph generates confidently wrong rules.

    A registry is built on demand when the caller has none, so the graph is
    always complete. An earlier version left the agent half empty for callers
    that did not pass one, and `policygen` then could not tell which agent owns
    which tool -- so every probe ran as a fallback agent that lacked the
    capability, and the resulting capability denials read as "path covered".
    A knowledge graph missing a third of its nodes does not report less; it
    reports wrongly.
    """
    st = state or seed_bank()
    if registry is None:
        from .identity import AgentRegistry
        registry = AgentRegistry()
    g = KnowledgeGraph()

    # data classes
    for s in Sensitivity:
        g.add(f"class:{s.label}", "LEVEL", str(int(s)))

    # customers and the data hanging off them
    for cid, cust in st.customers.items():
        node = f"customer:{cid}"
        g.add(node, HAS_EMAIL, f"email:{cust.email}")
        g.add(node, "TIER", f"tier:{cust.tier}")
        g.add(node, HAS_DATA, f"data:ssn:{cid}")
        g.add(f"data:ssn:{cid}", CLASSIFIED_AS, "class:pii")
        g.add(node, HAS_DATA, f"data:card:{cid}")
        g.add(f"data:card:{cid}", CLASSIFIED_AS, "class:pci")

    # tickets anchor a session to exactly one customer
    for tid, tk in st.tickets.items():
        g.add(f"ticket:{tid}", ABOUT, f"customer:{tk.customer_id}")
        g.add(f"ticket:{tid}", "STATUS", f"status:{tk.status}")

    # tools, described by their governance contract rather than their code
    for name, spec in SPECS.items():
        node = f"tool:{name}"
        if spec.reads > Sensitivity.PUBLIC:
            g.add(node, READS_CLASS, f"class:{spec.reads.label}")
        if spec.writes > Sensitivity.PUBLIC:
            g.add(node, WRITES_CLASS, f"class:{spec.writes.label}")
        if spec.egress:
            g.add(node, EGRESSES_TO, EXTERNAL)
        if spec.required_capability:
            g.add(node, REQUIRES_CAP, f"capability:{spec.required_capability}")

    # agents: ring and the capabilities they actually hold
    if registry is not None:
        for rec in registry.all():
            node = f"agent:{rec.key}"
            g.add(node, IN_RING, f"ring:{int(rec.ring)}")
            for cap in rec.capabilities:
                g.add(node, HOLDS_CAP, f"capability:{cap}")

    # the bridge to the procedure graph: which stage a tool completes, and
    # the declared order between stages. This is what lets one query answer
    # "may this tool run here?" across both graphs.
    for n in PROC_NODES:
        if n.completed_by:
            g.add(f"tool:{n.completed_by}", COMPLETES, f"stage:{n.key}")
        if n.owner:
            g.add(f"stage:{n.key}", "OWNED_BY", f"agent:{n.owner}")
    for e in PROC_EDGES:
        g.add(f"stage:{e.src}", PRECEDES, f"stage:{e.dst}")

    return g
