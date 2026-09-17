import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { Eye, EyeOff, Lock, KeyRound, ArrowRight, AlertTriangle } from "lucide-react";
import { resetPasswordSchema, ResetPasswordFormValues } from "@/utils/validators";
import { authApi } from "@/api/authApi";
import Input from "@/components/ui/Input";
import Button from "@/components/ui/Button";
import { useToast } from "@/hooks/useToast";
import { ROUTES } from "@/constants/routes";

export default function ResetPasswordPage() {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");

  const navigate = useNavigate();
  const { toast } = useToast();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<ResetPasswordFormValues>({
    resolver: zodResolver(resetPasswordSchema),
    defaultValues: { password: "", confirmPassword: "" },
  });

  async function onSubmit(values: ResetPasswordFormValues) {
    if (!token) {
      setError("Reset token is missing from the URL. Please request a new link.");
      return;
    }

    try {
      setIsLoading(true);
      setError(null);
      await authApi.resetPassword({
        token,
        new_password: values.password,
      });

      toast({
        title: "Password reset complete",
        description: "Your password has been updated. Please sign in with your new password.",
        variant: "success",
      });
      navigate(ROUTES.LOGIN);
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { detail?: string } } };
      const message =
        axiosError.response?.data?.detail || "Password reset failed. The link may have expired.";
      setError(message);
      toast({
        title: "Reset failed",
        description: message,
        variant: "error",
      });
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="glass-panel p-8 relative overflow-hidden">
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-accent-cyan/50 to-transparent" />

      <div className="flex items-center gap-2 mb-1">
        <KeyRound className="h-4 w-4 text-accent-cyan" />
        <span className="text-xs font-medium text-accent-cyan tracking-wide uppercase">
          Account Security
        </span>
      </div>
      <h1 className="font-display text-2xl font-semibold mb-1.5">Reset your password</h1>
      <p className="text-sm text-muted mb-7">
        Choose a strong new password for your ThreatLens account.
      </p>

      {!token ? (
        <div className="space-y-4">
          <div className="rounded-lg border border-severity-critical/30 bg-severity-critical/10 p-4 text-sm text-severity-critical flex items-start gap-2.5">
            <AlertTriangle className="h-5 w-5 shrink-0 mt-0.5" />
            <div>
              <p className="font-medium">Missing Reset Token</p>
              <p className="text-xs mt-1 text-slate-300">
                No password reset token was detected in the URL. Please request a new reset link.
              </p>
            </div>
          </div>
          <Link to={ROUTES.FORGOT_PASSWORD}>
            <Button variant="secondary" className="w-full">
              Request New Reset Link
            </Button>
          </Link>
        </div>
      ) : (
        <>
          {error && (
            <div className="mb-5 rounded-lg border border-severity-critical/30 bg-severity-critical/10 px-3.5 py-2.5 text-sm text-severity-critical">
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4" noValidate>
            <div>
              <label className="text-xs font-medium text-slate-400 mb-1.5 block">New password</label>
              <div className="relative">
                <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
                <Input
                  type={showPassword ? "text" : "password"}
                  placeholder="••••••••"
                  className="pl-10 pr-10"
                  error={errors.password?.message}
                  {...register("password")}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword((s) => !s)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {errors.password && (
                <p className="text-xs text-severity-critical mt-1.5">{errors.password.message}</p>
              )}
            </div>

            <div>
              <label className="text-xs font-medium text-slate-400 mb-1.5 block">Confirm new password</label>
              <div className="relative">
                <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
                <Input
                  type={showConfirmPassword ? "text" : "password"}
                  placeholder="••••••••"
                  className="pl-10 pr-10"
                  error={errors.confirmPassword?.message}
                  {...register("confirmPassword")}
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword((s) => !s)}
                  className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
                  aria-label={showConfirmPassword ? "Hide password" : "Show password"}
                >
                  {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {errors.confirmPassword && (
                <p className="text-xs text-severity-critical mt-1.5">
                  {errors.confirmPassword.message}
                </p>
              )}
            </div>

            <Button type="submit" className="w-full" size="lg" isLoading={isLoading}>
              {!isLoading && (
                <>
                  Update password <ArrowRight className="h-4 w-4" />
                </>
              )}
            </Button>

            <div className="text-center pt-2">
              <Link to={ROUTES.LOGIN} className="text-xs text-muted hover:text-slate-200">
                Cancel and back to Sign in
              </Link>
            </div>
          </form>
        </>
      )}
    </div>
  );
}
