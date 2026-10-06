import { useState, useEffect, useCallback, useRef } from 'react';
import { apiService } from '../services/api';
import { DashboardMetrics, ThreatFeedItem } from '../types';

export function useApiCall<T>(apiFunc: (...args: any[]) => Promise<T>) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<Error | null>(null);

  const execute = useCallback(async (...args: any[]) => {
    try {
      setLoading(true);
      setError(null);
      const result = await apiFunc(...args);
      setData(result);
      return result;
    } catch (err: any) {
      setError(err);
      throw err;
    } finally {
      setLoading(false);
    }
  }, [apiFunc]);

  return { data, loading, error, execute };
}

export function usePolling<T>(apiFunc: () => Promise<T>, interval = 30000) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const mountedRef = useRef(true);
  const busyRef = useRef(false);
  const apiFuncRef = useRef(apiFunc);
  useEffect(() => {
    apiFuncRef.current = apiFunc;
  }, [apiFunc]);

  const fetchData = useCallback(async (isInitial = false) => {
    if (busyRef.current) return;
    busyRef.current = true;
    try {
      if (isInitial) {
        setLoading(true);
      }
      const result = await apiFuncRef.current();
      if (mountedRef.current) { setData(result); setError(null); }
      return result;
    } catch (err: any) {
      if (mountedRef.current) setError(err);
    } finally {
      busyRef.current = false;
      if (isInitial && mountedRef.current) {
        setLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    fetchData(true);

    const timer = setInterval(() => {
      if (mountedRef.current && document.visibilityState === "visible") {
        fetchData(false);
      }
    }, interval);

    return () => {
      mountedRef.current = false;
      clearInterval(timer);
    };
  }, [fetchData, interval]);

  return { data, loading, error, refetch: () => fetchData(false) };
}

const fetchMetrics = () => apiService.getMetrics();
export function useMetrics(interval = 30000) {
  return usePolling<DashboardMetrics>(fetchMetrics, interval);
}

const fetchThreatFeed20 = () => apiService.getThreatFeed(20);
export function useThreatFeed(interval = 30000) {
  return usePolling<ThreatFeedItem[]>(fetchThreatFeed20, interval);
}
