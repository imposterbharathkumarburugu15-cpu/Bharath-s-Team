import * as React from "react"
import { cn } from "@/lib/utils"

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'outline' | 'ghost' | 'danger' | 'cyber' | 'emerald' | 'amber';
  size?: 'default' | 'sm' | 'lg' | 'icon' | 'xs';
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "default", ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center whitespace-nowrap rounded-xl text-xs font-semibold transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50 disabled:pointer-events-none disabled:opacity-40 cursor-pointer select-none",
          {
            "bg-cyan-500/15 text-cyan-300 border border-cyan-500/40 hover:bg-cyan-500/25 hover:border-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)]": variant === "default",
            "bg-gradient-to-r from-cyan-500 via-sky-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-slate-950 font-bold border border-cyan-300/60 shadow-[0_0_20px_rgba(6,182,212,0.35)]": variant === "cyber",
            "border border-slate-700/80 bg-slate-900/80 hover:bg-slate-800 hover:border-slate-600 text-slate-200": variant === "outline",
            "hover:bg-slate-800/80 text-slate-400 hover:text-slate-100": variant === "ghost",
            "bg-rose-500/15 text-rose-300 border border-rose-500/40 hover:bg-rose-500/25 hover:border-rose-400 shadow-[0_0_15px_rgba(244,63,94,0.2)]": variant === "danger",
            "bg-emerald-500/15 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/25 hover:border-emerald-400 shadow-[0_0_15px_rgba(16,185,129,0.2)]": variant === "emerald",
            "bg-amber-500/15 text-amber-300 border border-amber-500/40 hover:bg-amber-500/25 hover:border-amber-400 shadow-[0_0_15px_rgba(245,158,11,0.2)]": variant === "amber",
            "h-10 px-4 py-2": size === "default",
            "h-7 rounded-lg px-2.5 text-[11px]": size === "xs",
            "h-8 rounded-lg px-3 text-xs": size === "sm",
            "h-11 rounded-2xl px-6 text-sm font-bold": size === "lg",
            "h-9 w-9 p-0": size === "icon",
          },
          className
        )}
        {...props}
      />
    )
  }
)
Button.displayName = "Button"

export { Button }

