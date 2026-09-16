import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Link, useNavigate } from "react-router-dom";
import { Eye, EyeOff, Mail, Lock, User, UserPlus, ArrowRight } from "lucide-react";
import { registerSchema, RegisterFormValues } from "@/utils/validators";
import { authApi } from "@/api/authApi";
import { useAppDispatch } from "@/redux/hooks";
import { loginUser } from "@/redux/slices/authSlice";
import Input from "@/components/ui/Input";
import Button from "@/components/ui/Button";
import { useToast } from "@/hooks/useToast";
import { ROUTES } from "@/constants/routes";

export default function RegisterPage() {
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const dispatch = useAppDispatch();
  const navigate = useNavigate();
  const { toast } = useToast();

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<RegisterFormValues>({
    resolver: zodResolver(registerSchema),
    defaultValues: { fullName: "", email: "", password: "", confirmPassword: "" },
  });

  async function onSubmit(values: RegisterFormValues) {
    try {
      setIsLoading(true);
      setError(null);
      await authApi.signup({
        full_name: values.fullName,
        email: values.email,
        password: values.password,
      });

      // Automatically sign in the new user
      const loginResult = await dispatch(
        loginUser({ email: values.email, password: values.password })
      );

      if (loginUser.fulfilled.match(loginResult)) {
        toast({
          title: "Account created",
          description: "Welcome to ThreatLens. Signed in as Security Analyst.",
          variant: "success",
        });
        navigate(ROUTES.DASHBOARD);
      } else {
        toast({
          title: "Account created",
          description: "Please sign in with your new credentials.",
          variant: "success",
        });
        navigate(ROUTES.LOGIN);
      }
    } catch (err: unknown) {
      const axiosError = err as { response?: { data?: { detail?: string } } };
      const message =
        axiosError.response?.data?.detail || "Registration failed. Please try again.";
      setError(message);
      toast({
        title: "Registration failed",
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
        <UserPlus className="h-4 w-4 text-accent-cyan" />
        <span className="text-xs font-medium text-accent-cyan tracking-wide uppercase">
          New Analyst Registration
        </span>
      </div>
      <h1 className="font-display text-2xl font-semibold mb-1.5">Create your account</h1>
      <p className="text-sm text-muted mb-7">
        Get instant access to threat analysis, static scanning, and detection telemetry.
      </p>

      {error && (
        <div className="mb-5 rounded-lg border border-severity-critical/30 bg-severity-critical/10 px-3.5 py-2.5 text-sm text-severity-critical">
          {error}
        </div>
      )}

      <form onSubmit={handleSubmit(onSubmit)} className="space-y-4" noValidate>
        <div>
          <label className="text-xs font-medium text-slate-400 mb-1.5 block">Full name</label>
          <div className="relative">
            <User className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
            <Input
              type="text"
              placeholder="Jane Doe"
              className="pl-10"
              error={errors.fullName?.message}
              {...register("fullName")}
            />
          </div>
          {errors.fullName && (
            <p className="text-xs text-severity-critical mt-1.5">{errors.fullName.message}</p>
          )}
        </div>

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

        <div>
          <label className="text-xs font-medium text-slate-400 mb-1.5 block">Password</label>
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
          <label className="text-xs font-medium text-slate-400 mb-1.5 block">Confirm password</label>
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
              Create account <ArrowRight className="h-4 w-4" />
            </>
          )}
        </Button>

        <div className="text-center pt-2">
          <span className="text-xs text-muted">Already have an account? </span>
          <Link to={ROUTES.LOGIN} className="text-xs text-accent-cyan hover:underline font-medium">
            Sign in
          </Link>
        </div>
      </form>
    </div>
  );
}
