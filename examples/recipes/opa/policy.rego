# The trading-desk rules of examples/iam_cedar/policies.cedar, written for OPA.
# lockwalk's decide() recipe posts {subject, action, resource, context} as the input.
package lockwalk

import rego.v1

# Fail closed: anything no rule allows is a deny, and `result` is always present.
default allow := false

market_actions := {"market:read", "market:quote", "market:confirm"}

# Analysts and traders may read market data.
allow if {
	input.subject.type == "user"
	input.action.name in market_actions
	input.resource.type == "stock_symbol"
	some role in input.subject.properties.roles
	role in {"analyst", "trader"}
}

# Agents may read market data too.
allow if {
	input.subject.type == "agent"
	input.action.name in market_actions
	input.resource.type == "stock_symbol"
}

# A user reads only their own portfolio.
allow if {
	input.subject.type == "user"
	input.action.name == "portfolio:read"
	input.resource.type == "portfolio"
	input.resource.properties.owner == input.subject.id
}

# A trader trades only from their own account.
allow if {
	input.subject.type == "user"
	input.action.name == "trade:execute"
	input.resource.type == "order"
	some role in input.subject.properties.roles
	role == "trader"
	input.resource.properties.account_owner == input.subject.id
}

# DELIBERATE HOLE, which lockwalk test finds: trade-agent's own service identity may
# trade on any account.
allow if {
	input.subject.type == "agent"
	input.subject.id == "trade-agent"
	input.action.name == "trade:execute"
	input.resource.type == "order"
}

# Anyone may invoke any agent (asked only with [policy] ask_every_hop = true).
allow if {
	input.action.name == "agent:invoke"
	input.resource.type == "agent"
}
