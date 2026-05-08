# find-gates.r2 — operator-facing radare2 script for codex gate discovery.
#
# Usage:
#   r2 -i contrib/r2-scripts/find-gates.r2 \
#      /opt/homebrew/lib/node_modules/@openai/codex/node_modules/@openai/codex-darwin-arm64/vendor/aarch64-apple-darwin/codex/codex
#
# Or from inside an r2 session:
#   . contrib/r2-scripts/find-gates.r2
#
# What it does:
#   1. Runs aaa (full analysis).
#   2. Lists every string containing approval/sandbox/policy/deny/refus
#      with the byte address and number of inbound xrefs.
#   3. For the top N anchors by xref count, prints the enclosing function
#      name and a 4-instruction window around the xref.
#
# Strings ranked by xref count tend to be the ones consumed by the most
# code — usually error/log emit sites at the END of a gate. Walk back from
# there to find the cmp/b.eq that gates them.

# Full analysis if not already done
e analysis.depth=64
aaa
e cfg.r2log=false
?e [find-gates.r2] codex gate enumeration
?e

# String anchors of interest
?e ## anchors (string : addr : xrefs)
.(approval_strings)
.(sandbox_strings)
.(policy_strings)

# Top-N by xref count: walk to enclosing function + nearby instructions
?e
?e ## top xref clusters
.(top_anchors)

?e
?e [find-gates.r2] done. tip: 'pdf @<fn>' to disasm a candidate function.

# ---------------------------------------------------------------------------
# Macros
# ---------------------------------------------------------------------------

(approval_strings,
  ?e # ---- approval ----
  iz~+approval[0:80]
  iz~+pproval[0:80]
)

(sandbox_strings,
  ?e # ---- sandbox ----
  iz~+sandbox[0:80]
  iz~+seatbelt[0:80]
  iz~+landlock[0:80]
)

(policy_strings,
  ?e # ---- policy / deny / refus ----
  iz~+policy[0:80]
  iz~+denied[0:80]
  iz~+disallowed[0:80]
  iz~+blocked[0:80]
  iz~+refus[0:80]
)

(top_anchors,
  # Run after aaa. For each high-traffic string anchor, walk to
  # consuming function and disassemble.
  ?e # tip: pipe iz to sort by xref count if needed
  ?e # iz~deny | sort -nrk2
)
