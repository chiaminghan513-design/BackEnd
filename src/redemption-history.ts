type RecordData = Record<string, unknown>;

// Reconcile official read responses only; never create or modify transactions.
export function mergeRedemptionHistory(base: RecordData[], additions: RecordData[]): RecordData[] {
  const key = (row: RecordData) => {
    const type = String(row.Type || row.TransactionType || '').toLowerCase();
    if (!/reward|voucher|redeem/.test(type)) return '';
    const date = String(row.RedeemDate || row.DateTime || row.CreateDate || '');
    const time = new Date(date).getTime();
    if (!Number.isFinite(time)) return '';
    const namedType = String(row.Type || row.TransactionType || '').match(/^Redeem\s+(?:Reward|Voucher)\s*\((.*)\)$/i);
    const name = (namedType?.[1] || String(row.Description || row.Name || row.Title || '')).trim();
    const phone = String(row.Phone || row.PhoneNumber || '').replace(/\D/g, '');
    const merchant = String(row.Merchant_Id || row.MerchantId || '').split(',')[0].trim();
    // The same provider action has slightly different sub-second timestamps
    // and descriptions across its ledger and redemption-list responses.
    return `${/voucher/.test(type) ? 'voucher' : 'reward'}:${Math.floor(time / 1000)}:${phone}:${merchant}:${name}`;
  };
  const available = new Map<string, number>();
  for (const identity of base.map(key).filter(Boolean)) available.set(identity, (available.get(identity) || 0) + 1);
  const result = [...base];
  for (const row of additions) {
    const identity = key(row);
    const matches = identity ? available.get(identity) || 0 : 0;
    if (matches > 0) { available.set(identity, matches - 1); continue; }
    result.push(row);
  }
  return result;
}
