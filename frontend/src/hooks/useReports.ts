import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { reportService, type ListReportsParams } from "@/services/reportService";

export function useReports(params: ListReportsParams) {
  return useQuery({
    queryKey: ["reports", params],
    queryFn: () => reportService.list(params),
    placeholderData: (previous) => previous,
  });
}

export function useReport(id: string | undefined) {
  return useQuery({
    queryKey: ["report", id],
    queryFn: () => reportService.get(id as string),
    enabled: Boolean(id),
  });
}

export function useGenerateReport() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({
      investigationIds,
      title,
    }: {
      investigationIds: string[];
      title?: string;
    }) => reportService.generate(investigationIds, title),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
    },
  });
}

export function useDeleteReport() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (id: string) => reportService.remove(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
    },
  });
}
