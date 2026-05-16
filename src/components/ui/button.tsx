import * as React from "react"
import { cn } from "@/lib/utils"

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'outline' | 'ghost' | 'danger';
  size?: 'default' | 'sm' | 'lg' | 'icon';
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "default", size = "default", ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          "inline-flex items-center justify-center whitespace-nowrap rounded-md text-sm font-medium transition-all focus-visible:outline-none disabled:pointer-events-none disabled:opacity-50",
          {
            "bg-cyber-blue/10 text-cyber-blue border border-cyber-blue/50 hover:bg-cyber-blue/20 hover:cyber-glow-blue": variant === "default",
            "border border-cyber-border bg-transparent hover:bg-cyber-blue/10 text-cyber-text": variant === "outline",
            "hover:bg-cyber-panel text-cyber-muted hover:text-cyber-text": variant === "ghost",
            "bg-cyber-red/10 text-cyber-red border border-cyber-red/50 hover:bg-cyber-red/20 hover:cyber-glow-red": variant === "danger",
            "h-10 px-4 py-2": size === "default",
            "h-9 rounded-md px-3": size === "sm",
            "h-11 rounded-md px-8 text-base": size === "lg",
            "h-10 w-10": size === "icon",
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
