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
    <p className={cn('text-sm text-muted-foreground', className)} {...props}>
      {children}
    </p>
  );
}

export function SmallMutedText({ children, className, ...props }: React.ComponentProps<'p'>) {
  return (
    <p className={cn('text-xs text-foreground opacity-75', className)} {...props}>
      {children}
    </p>
  );
}
