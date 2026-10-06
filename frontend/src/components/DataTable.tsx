import React, { useState, useMemo } from 'react';
import clsx from 'clsx';
import {
  ChevronLeft, ChevronRight, ChevronsLeft, ChevronsRight,
  Search, SlidersHorizontal
} from 'lucide-react';
import { EmptyState, LoadingSkeleton } from './EmptyState';

export interface Column<T> {
  key: string;
  header: string;
  render?: (item: T) => React.ReactNode;
  align?: 'left' | 'center' | 'right';
  width?: string;
  sortable?: boolean;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  data: T[];
  loading?: boolean;
  searchable?: boolean;
  searchPlaceholder?: string;
  searchFilter?: (item: T, query: string) => boolean;
  onRowClick?: (item: T) => void;
  rowKey: (item: T) => string;
  initialPageSize?: number;
  emptyTitle?: string;
  emptyDescription?: string;
  className?: string;
  defaultDensity?: 'compact' | 'comfortable';
}

export default function DataTable<T>({
  columns,
  data,
  loading = false,
  searchable = true,
  searchPlaceholder = 'Filter records...',
  searchFilter,
  onRowClick,
  rowKey,
  initialPageSize = 15,
  emptyTitle,
  emptyDescription,
  className,
  defaultDensity = 'comfortable',
}: DataTableProps<T>) {
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(initialPageSize);
  const [density, setDensity] = useState<'compact' | 'comfortable'>(defaultDensity);

  // Search filtering
  const filteredData = useMemo(() => {
    if (!query.trim()) return data;
    if (searchFilter) {
      return data.filter(item => searchFilter(item, query.toLowerCase()));
    }
    // Default search across all stringifiable values
    return data.filter(item => {
      const serialized = JSON.stringify(item).toLowerCase();
      return serialized.includes(query.toLowerCase());
    });
  }, [data, query, searchFilter]);

  // Pagination calculations
  const totalPages = Math.max(1, Math.ceil(filteredData.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const paginatedData = useMemo(() => {
    const start = (currentPage - 1) * pageSize;
    return filteredData.slice(start, start + pageSize);
  }, [filteredData, currentPage, pageSize]);

  const paddingY = density === 'compact' ? 'py-1.5' : 'py-3';
  const fontSize = density === 'compact' ? 'text-xs' : 'text-sm';

  return (
    <div className={clsx('flex flex-col bg-[#111827] border border-[#263247] rounded-lg overflow-hidden', className)}>
      {/* Control Bar: Search + Density + Counter */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between p-3 border-b border-[#263247] bg-[#0E1526] gap-3">
        <div className="flex items-center gap-2 flex-1 max-w-md">
          {searchable && (
            <div className="relative w-full">
              <Search size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#8F9BAD]" />
              <input
                type="text"
                value={query}
                onChange={(e) => {
                  setQuery(e.target.value);
                  setPage(1);
                }}
                placeholder={searchPlaceholder}
                className="w-full bg-[#111827] border border-[#263247] rounded pl-8 pr-3 py-1.5 text-xs text-[#F4F7FB] placeholder-[#647083] focus:outline-none focus:border-[#4F8CFF] focus:ring-1 focus:ring-[#4F8CFF]"
              />
            </div>
          )}
        </div>

        <div className="flex items-center gap-3 self-end sm:self-auto">
          {/* Density Toggle */}
          <div className="flex items-center border border-[#263247] rounded bg-[#111827] p-0.5 text-xs">
            <button
              onClick={() => setDensity('compact')}
              className={clsx(
                'px-2 py-0.5 rounded font-mono text-[11px] transition-colors',
                density === 'compact' ? 'bg-[#172033] text-[#4F8CFF] font-semibold' : 'text-[#8F9BAD] hover:text-[#F4F7FB]'
              )}
              title="Compact density"
            >
              Compact
            </button>
            <button
              onClick={() => setDensity('comfortable')}
              className={clsx(
                'px-2 py-0.5 rounded font-mono text-[11px] transition-colors',
                density === 'comfortable' ? 'bg-[#172033] text-[#4F8CFF] font-semibold' : 'text-[#8F9BAD] hover:text-[#F4F7FB]'
              )}
              title="Comfortable density"
            >
              Comfortable
            </button>
          </div>

          <span className="text-xs text-[#8F9BAD] font-mono">
            {filteredData.length} records
          </span>
        </div>
      </div>

      {/* Table Area */}
      {loading && data.length === 0 ? (
        <LoadingSkeleton rows={6} />
      ) : filteredData.length === 0 ? (
        <EmptyState title={emptyTitle} description={emptyDescription} />
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-[#263247] bg-[#0E1526] text-[11px] uppercase tracking-wider text-[#8F9BAD] font-mono select-none">
                {columns.map((col) => (
                  <th
                    key={col.key}
                    style={{ width: col.width }}
                    className={clsx(
                      'px-3.5 py-2.5 font-semibold',
                      col.align === 'right' ? 'text-right' : col.align === 'center' ? 'text-center' : 'text-left'
                    )}
                  >
                    {col.header}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className={clsx('divide-y divide-[#1D2738]', fontSize)}>
              {paginatedData.map((item) => (
                <tr
                  key={rowKey(item)}
                  onClick={() => onRowClick && onRowClick(item)}
                  className={clsx(
                    'transition-colors duration-100',
                    onRowClick ? 'cursor-pointer hover:bg-[#172033]' : 'hover:bg-[#141E30]'
                  )}
                >
                  {columns.map((col) => (
                    <td
                      key={col.key}
                      className={clsx(
                        'px-3.5',
                        paddingY,
                        col.align === 'right' ? 'text-right' : col.align === 'center' ? 'text-center' : 'text-left'
                      )}
                    >
                      {col.render ? col.render(item) : (item as any)[col.key]}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination Footer */}
      {filteredData.length > 0 && (
        <div className="flex flex-col sm:flex-row sm:items-center justify-between px-4 py-2.5 border-t border-[#263247] bg-[#0E1526] text-xs text-[#8F9BAD] gap-2">
          <div className="flex items-center gap-2">
            <span>Rows per page:</span>
            <select
              value={pageSize}
              onChange={(e) => {
                setPageSize(Number(e.target.value));
                setPage(1);
              }}
              className="bg-[#111827] border border-[#263247] text-[#F4F7FB] rounded px-2 py-0.5 focus:outline-none focus:border-[#4F8CFF]"
            >
              {[10, 15, 25, 50, 100].map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>

          <div className="flex items-center gap-2 font-mono">
            <span>
              Page {currentPage} of {totalPages}
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage(1)}
                disabled={currentPage <= 1}
                aria-label="First page"
                className="p-1 rounded hover:bg-[#172033] disabled:opacity-30 disabled:hover:bg-transparent"
              >
                <ChevronsLeft size={14} />
              </button>
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={currentPage <= 1}
                aria-label="Previous page"
                className="p-1 rounded hover:bg-[#172033] disabled:opacity-30 disabled:hover:bg-transparent"
              >
                <ChevronLeft size={14} />
              </button>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={currentPage >= totalPages}
                aria-label="Next page"
                className="p-1 rounded hover:bg-[#172033] disabled:opacity-30 disabled:hover:bg-transparent"
              >
                <ChevronRight size={14} />
              </button>
              <button
                onClick={() => setPage(totalPages)}
                disabled={currentPage >= totalPages}
                aria-label="Last page"
                className="p-1 rounded hover:bg-[#172033] disabled:opacity-30 disabled:hover:bg-transparent"
              >
                <ChevronsRight size={14} />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
