import { cn } from '~/lib/utils';

export function Title({ children, className, ...props }: React.ComponentProps<'h1'>) {
  return (
    <h1 className={cn('text-5xl font-bold text-center')} {...props}>
      {children}
    </h1>
  );
}

export function MutedText({ children, className, ...props }: React.ComponentProps<'p'>) {
  return (
    <p className={cn('text-sm text-muted-foreground')} {...props}>
      {children}
    </p>
  );
}
