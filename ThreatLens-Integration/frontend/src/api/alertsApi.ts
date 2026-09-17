import { Alert } from "@/types/alert.types";
import axiosInstance from "./axiosInstance";

/**
 * AlertOut (backend/app/alerts/schemas.py) is already camelCase and matches
 * the Alert interface field for field, so these need no mapping layer.
 */
export const alertsApi = {
  getAlerts: async (): Promise<Alert[]> => {
    const { data } = await axiosInstance.get<Alert[]>("/alerts", {
      params: { limit: 100 },
    });
    return data;
  },

  markAsRead: async (id: string): Promise<{ id: string }> => {
    await axiosInstance.patch(`/alerts/${id}/read`);
    return { id };
  },

  deleteAlert: async (id: string): Promise<{ id: string }> => {
    await axiosInstance.delete(`/alerts/${id}`);
    return { id };
  },
};
