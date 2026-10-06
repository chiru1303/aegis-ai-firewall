import React from 'react';
import { LucideIcon, FolderSearch, RefreshCw } from 'lucide-react';
import clsx from 'clsx';

interface EmptyStateProps {
  title?: string;
  description?: string;
  icon?: LucideIcon;
  actionText?: string;
  onAction?: () => void;
  className?: string;
}

export function EmptyState({
  title = 'No records found',
  description = 'There is no data matching your current filters or query.',
  icon: Icon = FolderSearch,
  actionText,
  onAction,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={clsx(
        'w-full py-12 px-4 flex flex-col items-center justify-center text-center bg-[#111827] border border-dashed border-[#263247] rounded-lg',
        className
      )}
      role="status"
    >
      <div className="p-3 bg-[#172033] border border-[#263247] rounded-full text-[#8F9BAD] mb-3">
        <Icon size={24} aria-hidden="true" />
      </div>
      <h3 className="text-sm font-semibold text-[#F4F7FB]">{title}</h3>
      <p className="text-xs text-[#8F9BAD] max-w-sm mt-1 mb-4">{description}</p>
      {actionText && onAction && (
        <button
          onClick={onAction}
          className="px-3 py-1.5 bg-[#172033] hover:bg-[#1D2940] text-xs font-medium text-[#4F8CFF] border border-[#263247] rounded transition-colors"
        >
          {actionText}
        </button>
      )}
    </div>
  );
}

interface ErrorStateProps {
  title?: string;
  message?: string;
  onRetry?: () => void;
  className?: string;
}

export function ErrorState({
  title = 'Failed to load telemetry',
  message = 'An unexpected network error occurred while communicating with the gateway.',
  onRetry,
  className,
}: ErrorStateProps) {
  return (
    <div
      className={clsx(
        'w-full py-10 px-4 flex flex-col items-center justify-center text-center bg-[rgba(239,98,111,0.06)] border border-[rgba(239,98,111,0.25)] rounded-lg',
        className
      )}
      role="alert"
    >
      <h3 className="text-sm font-semibold text-[#EF626F]">{title}</h3>
      <p className="text-xs text-[#C0C8D6] max-w-md mt-1 mb-4 font-mono">{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#172033] hover:bg-[#1D2940] text-xs font-medium text-[#F4F7FB] border border-[#263247] rounded transition-colors"
        >
          <RefreshCw size={13} className="shrink-0" />
          <span>Retry Request</span>
        </button>
      )}
    </div>
  );
}

export function LoadingSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="w-full space-y-2.5 animate-pulse p-4 bg-[#111827] border border-[#263247] rounded-lg">
      <div className="h-4 bg-[#172033] rounded w-1/4 mb-4"></div>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4">
          <div className="h-3.5 bg-[#172033] rounded w-1/6"></div>
          <div className="h-3.5 bg-[#172033] rounded w-2/6"></div>
          <div className="h-3.5 bg-[#172033] rounded w-1/6"></div>
          <div className="h-3.5 bg-[#172033] rounded w-2/6"></div>
        </div>
      ))}
    </div>
  );
}

export default EmptyState;
