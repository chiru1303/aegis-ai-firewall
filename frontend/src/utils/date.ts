export interface FormatISTOptions {
  showSeconds?: boolean;
  dateOnly?: boolean;
  timeOnly?: boolean;
  showTzLabel?: boolean;
}

/** Formats timestamps consistently in India Standard Time without ambiguous numeric dates. */
export function formatIST(
  value: string | number | Date | null | undefined,
  options?: FormatISTOptions,
): string {
  if (value === null || value === undefined || value === '') return 'N/A';

  let date: Date;
  if (typeof value === 'string') {
    const local = value.trim().match(/^(\d{2})\/(\d{2})\/(\d{4})(?:\s+(\d{2}):(\d{2})(?::(\d{2}))?)?(?:\s+IST)?$/i);
    if (local) {
      const [, day, month, year, hour = '0', minute = '0', second = '0'] = local;
      date = new Date(Date.UTC(Number(year), Number(month) - 1, Number(day), Number(hour) - 5, Number(minute) - 30, Number(second)));
    } else if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}/.test(value)) {
      date = new Date(value.trim().replace(' ', 'T') + 'Z');
    } else {
      date = new Date(value);
    }
  } else if (typeof value === 'number') {
    date = new Date(value > 1e11 ? value : value * 1000);
  } else {
    date = value;
  }

  if (Number.isNaN(date.getTime())) return typeof value === 'string' ? value : 'N/A';

  const dateOptions: Intl.DateTimeFormatOptions = options?.dateOnly
    ? { day: 'numeric', month: 'short', year: 'numeric' }
    : options?.timeOnly
      ? { hour: 'numeric', minute: '2-digit', ...(options.showSeconds ? { second: '2-digit' as const } : {}), hour12: true }
      : { day: 'numeric', month: 'short', year: 'numeric', hour: 'numeric', minute: '2-digit', ...(options?.showSeconds ? { second: '2-digit' as const } : {}), hour12: true };

  const formatted = new Intl.DateTimeFormat('en-GB', { ...dateOptions, timeZone: 'Asia/Kolkata' })
    .format(date)
    .replace(/\b(am|pm)\b/gi, part => part.toUpperCase());
  return options?.showTzLabel === false || options?.dateOnly ? formatted : `${formatted} IST`;
}

export function nowIST(includeSeconds = false): string {
  return formatIST(new Date(), { showSeconds: includeSeconds });
}
