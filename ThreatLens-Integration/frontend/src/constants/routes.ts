export const ROUTES = {
  LOGIN: "/login",
  REGISTER: "/register",
  FORGOT_PASSWORD: "/forgot-password",
  RESET_PASSWORD: "/reset-password",
  DASHBOARD: "/",
  UPLOAD: "/upload",
  REPORTS: "/reports",
  ANALYTICS: "/analytics",
  ALERTS: "/alerts",
  THREAT_DETAILS: "/threats/:id",
  threatDetails: (id: string) => `/threats/${id}`,
  SETTINGS: "/settings",
} as const;
