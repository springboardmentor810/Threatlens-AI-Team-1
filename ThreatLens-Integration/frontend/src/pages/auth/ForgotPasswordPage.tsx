import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Link } from "react-router-dom";
import { Mail, KeyRound, ArrowRight, ArrowLeft, ExternalLink, CheckCircle } from "lucide-react";
import { forgotPasswordSchema, ForgotPasswordFormValues } from "@/utils/validators";
import { authApi } from "@/api/authApi";
import Input from "@/components/ui/Input";
import Button from "@/components/ui/Button";
import { useToast } from "@/hooks/useToast";
import { ROUTES } from "@/constants/routes";

export default function ForgotPasswordPage() {
  const [isLoading, setIsLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [devResetLink, setDevResetLink] = useState<string | null>(null);

  const { toast } = useToast();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<ForgotPasswordFormValues>({
    resolver: zodResolver(forgotPasswordSchema),
    defaultValues: { email: "" },
  });

  async function onSubmit(values: ForgotPasswordFormValues) {
    try {
      setIsLoading(true);
      const res = await authApi.forgotPassword(values.email);
      setSubmitted(true);
      if (res.dev_reset_link) {
        setDevResetLink(res.dev_reset_link);
      }
      toast({
        title: "Request submitted",
        description: res.message,
        variant: "info",
      });
    } catch {
      toast({
        title: "Request failed",
        description: "An unexpected error occurred. Please try again.",
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
          Password Recovery
        </span>
      </div>
      <h1 className="font-display text-2xl font-semibold mb-1.5">Forgot your password?</h1>
      <p className="text-sm text-muted mb-7">
        Enter your registered email address and we'll send you instructions to reset your password.
      </p>

      {submitted ? (
        <div className="space-y-5">
          <div className="rounded-lg border border-accent-cyan/30 bg-accent-cyan/10 p-4 text-sm text-slate-200 flex items-start gap-3">
            <CheckCircle className="h-5 w-5 text-accent-cyan shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-slate-100">Check your inbox</p>
              <p className="text-xs text-muted mt-1">
                If an account exists with that address, we have dispatched a password reset link. The link remains valid for 15 minutes.
              </p>
            </div>
          </div>

          {devResetLink && (
            <div className="rounded-lg border border-severity-medium/30 bg-severity-medium/10 p-4 text-xs space-y-2">
              <p className="font-semibold text-severity-medium flex items-center gap-1.5">
                <span>[Development Mode] Local Reset Link:</span>
              </p>
              <p className="text-slate-300 break-all font-mono">
                <a
                  href={devResetLink}
                  className="text-accent-cyan hover:underline inline-flex items-center gap-1"
                >
                  {devResetLink} <ExternalLink className="h-3 w-3" />
                </a>
              </p>
            </div>
          )}

          <div className="pt-2">
            <Link to={ROUTES.LOGIN}>
              <Button variant="secondary" className="w-full" size="lg">
                <ArrowLeft className="h-4 w-4" /> Back to Sign in
              </Button>
            </Link>
          </div>
        </div>
      ) : (
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4" noValidate>
          <div>
            <label className="text-xs font-medium text-slate-400 mb-1.5 block">Email address</label>
            <div className="relative">
              <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <Input
                type="email"
                placeholder="you@company.com"
                className="pl-10"
                error={errors.email?.message}
                {...register("email")}
              />
            </div>
            {errors.email && (
              <p className="text-xs text-severity-critical mt-1.5">{errors.email.message}</p>
            )}
          </div>

          <Button type="submit" className="w-full" size="lg" isLoading={isLoading}>
            {!isLoading && (
              <>
                Send reset link <ArrowRight className="h-4 w-4" />
              </>
            )}
          </Button>

          <div className="text-center pt-2">
            <Link to={ROUTES.LOGIN} className="text-xs text-muted hover:text-slate-200 inline-flex items-center gap-1">
              <ArrowLeft className="h-3 w-3" /> Back to Sign in
            </Link>
          </div>
        </form>
      )}
    </div>
  );
}
