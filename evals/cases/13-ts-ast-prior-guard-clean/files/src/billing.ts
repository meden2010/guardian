import { InvoiceConfig } from "./config";

export function computePerSeatCents(
  totalCents: number,
  discountCents: number,
  seats: number,
  cfg: InvoiceConfig
): number {
  if (seats <= 0) {
    return 0;
  }
  if (totalCents <= 0) {
    return 0;
  }
  const _currency = cfg.currency;
  const taxable = totalCents - discountCents;
  const net = Math.max(0, taxable);
  return Math.round(net / seats);
}
