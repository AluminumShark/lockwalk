// Analysts and traders may read market data.
permit (
  principal is User,
  action in [Action::"market:read", Action::"market:quote", Action::"market:confirm"],
  resource is StockSymbol
) when { principal.roles.contains("analyst") || principal.roles.contains("trader") };

// Agents may read market data too.
permit (
  principal is Agent,
  action in [Action::"market:read", Action::"market:quote", Action::"market:confirm"],
  resource is StockSymbol
);

// BROKEN: the owner check on portfolios is gone, any analyst or trader reads any portfolio.
permit (principal is User, action == Action::"portfolio:read", resource is Portfolio)
when { principal.roles.contains("analyst") || principal.roles.contains("trader") };

// A trader trades only from their own account.
permit (principal is User, action == Action::"trade:execute", resource is Order)
when {
  principal.roles.contains("trader") &&
  resource has account_owner && resource.account_owner == principal.name
};

// DELIBERATE HOLE, which lockwalk test finds: trade-agent's own service identity may
// trade on any account.
permit (principal == Agent::"trade-agent", action == Action::"trade:execute", resource is Order);

// Anyone may invoke any agent (asked only with [policy] ask_every_hop = true).
permit (principal, action == Action::"agent:invoke", resource is Agent);
