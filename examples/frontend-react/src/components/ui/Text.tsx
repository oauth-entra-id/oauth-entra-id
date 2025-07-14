import { cn } from '~/lib/utils';

export function Title({ children, className, ...props }: React.ComponentProps<'h1'>) {
  return (
    <h1 className={cn('text-5xl font-bold text-center', className)} {...props}>
      {children}
    </h1>
  );
}

export function MutedText({ children, className, ...props }: React.ComponentProps<'p'>) {
  return (
    <div className={cn('text-sm text-muted-foreground', className)} {...props}>
      {children}
    </div>
  );
}

export function SmallMutedText({ children, className, ...props }: React.ComponentProps<'p'>) {
  return (
    <div className={cn('text-xs text-foreground opacity-65', className)} {...props}>
      {children}
    </div>
  );
}
