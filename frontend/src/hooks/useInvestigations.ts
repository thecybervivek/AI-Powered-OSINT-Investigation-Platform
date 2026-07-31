import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  investigationService,
  type ListInvestigationsParams,
} from "@/services/investigationService";

export function useInvestigations(params: ListInvestigationsParams) {
  return useQuery({
    queryKey: ["investigations", params],
    queryFn: () => investigationService.list(params),
    placeholderData: (previous) => previous,
  });
}

// Investigations that haven't reached a terminal state yet are
// polled so the result page updates on its own as evidence sources
// complete - this is a real signal (re-fetching the actual record),
// not a fabricated progress animation. Polling stops the moment the
// investigation reaches a terminal status.
const ACTIVE_STATUSES = new Set(["queued", "running"]);
const POLL_INTERVAL_MS = 4000;

export function useInvestigation(id: string | undefined) {
  return useQuery({
    queryKey: ["investigation", id],
    queryFn: () => investigationService.get(id as string),
    enabled: Boolean(id),
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && ACTIVE_STATUSES.has(status) ? POLL_INTERVAL_MS : false;
    },
  });
}

export function useDeleteInvestigation() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => investigationService.remove(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["investigations"] });
    },
  });
}
