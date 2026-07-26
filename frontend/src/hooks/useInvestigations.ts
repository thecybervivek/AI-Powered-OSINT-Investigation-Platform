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

export function useInvestigation(id: string | undefined) {
  return useQuery({
    queryKey: ["investigation", id],
    queryFn: () => investigationService.get(id as string),
    enabled: Boolean(id),
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
